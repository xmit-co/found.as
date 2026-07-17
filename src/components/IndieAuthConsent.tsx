import { deriveKP, mintIndieAuthCode, resolveIndieAuthMe } from "../api";
import { t, tx } from "../i18n";
import { rememberPage, rememberedKeyPair } from "../storage";
import { useEffect, useState } from "preact/hooks";
import { SignKeyPair } from "tweetnacl";

// The IndieAuth issuer, matching the backend metadata document.
const ISSUER = "https://be.found.as/";

interface AuthRequest {
  clientId: string;
  redirectUri: string;
  state: string;
  me: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope: string;
  responseType: string;
}

function parseRequest(): AuthRequest | null {
  const q = new URLSearchParams(location.search);
  const clientId = q.get("client_id") ?? "";
  const redirectUri = q.get("redirect_uri") ?? "";
  if (!clientId || !redirectUri) return null;
  return {
    clientId,
    redirectUri,
    me: q.get("me") ?? "",
    state: q.get("state") ?? "",
    codeChallenge: q.get("code_challenge") ?? "",
    codeChallengeMethod: q.get("code_challenge_method") ?? "",
    scope: q.get("scope") ?? "",
    responseType: q.get("response_type") ?? "code",
  };
}

function hostOf(value: string): string {
  try {
    return new URL(value).host;
  } catch {
    return value;
  }
}

type Phase = "loading" | "ready" | "submitting" | "error";

export function IndieAuthConsent() {
  const [req] = useState(parseRequest);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState("");
  const [path, setPath] = useState("");
  const [displayMe, setDisplayMe] = useState("");
  const [keyPair, setKeyPair] = useState<SignKeyPair | null>(null);
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);

  // Resolve the identity to a page path (so we can load its key), and see
  // whether this browser already remembers that page's key.
  useEffect(() => {
    if (!req) {
      setError(t("This sign-in request is missing required details."));
      setPhase("error");
      return;
    }
    if (req.responseType !== "code") {
      setError(t("This sign-in request isn't supported."));
      setPhase("error");
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        let resolvedPath: string;
        let me: string;
        const url = new URL(req.me);
        if (url.host === "found.as") {
          const seg = url.pathname.replace(/^\/+/, "").replace(/\/+$/, "");
          if (!seg || seg.includes("/")) throw new Error("not a page");
          resolvedPath = decodeURIComponent(seg);
          me = `https://found.as/${seg}`;
        } else {
          const r = await resolveIndieAuthMe(req.me);
          resolvedPath = r.path;
          me = r.me;
        }
        if (cancelled) return;
        setPath(resolvedPath);
        setDisplayMe(me);
        setKeyPair(rememberedKeyPair(resolvedPath));
        setPhase("ready");
      } catch (e) {
        if (cancelled) return;
        setError(
          e instanceof Error && e.message !== "not a page"
            ? e.message
            : t("This address isn't a found.as page."),
        );
        setPhase("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const redirectBack = (params: Record<string, string>) => {
    const url = new URL(req!.redirectUri);
    for (const [k, v] of Object.entries(params))
      if (v) url.searchParams.set(k, v);
    if (req!.state) url.searchParams.set("state", req!.state);
    location.assign(url.toString());
  };

  const approve = async (e: Event) => {
    e.preventDefault();
    if (!req) return;
    setError("");
    setPhase("submitting");
    try {
      const kp = keyPair ?? (await deriveKP(path, password));
      const { code } = await mintIndieAuthCode(kp, {
        me: displayMe,
        clientId: req.clientId,
        redirectUri: req.redirectUri,
        codeChallenge: req.codeChallenge,
        codeChallengeMethod: req.codeChallengeMethod,
        scope: req.scope,
      });
      // Only after the mint confirms the key is correct, and only if the user
      // derived it from a password here and opted in.
      if (!keyPair && remember) rememberPage(path, kp);
      redirectBack({ code, iss: ISSUER });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(
        /Invalid public key|403|Forbidden/.test(msg)
          ? t("That password doesn't match this page.")
          : msg,
      );
      setPhase("ready");
    }
  };

  const deny = () => {
    if (req) redirectBack({ error: "access_denied" });
  };

  if (phase === "error") {
    return (
      <div className="app-shell">
        <main className="setup-panel">
          <div className="setup-copy">
            <p className="eyebrow">{t("Sign in")}</p>
            <h1>{t("Can't sign in")}</h1>
            <p className="help error-text">{error}</p>
          </div>
        </main>
      </div>
    );
  }

  if (phase === "loading") {
    return (
      <div className="app-shell">
        <main className="setup-panel">
          <p className="help">{t("Checking this sign-in request…")}</p>
        </main>
      </div>
    );
  }

  const clientHost = hostOf(req!.clientId);
  const identity = displayMe.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const needsPassword = !keyPair;
  const scopes = req!.scope.split(/\s+/).filter(Boolean);

  return (
    <div className="app-shell">
      <main className="setup-panel">
        <div className="setup-copy">
          <p className="eyebrow">
            {scopes.length ? t("Authorize") : t("Sign in")}
          </p>
          <h1>{t("Continue as {identity}", { identity })}</h1>
          {scopes.length ? (
            <>
              <p className="help">
                {tx(
                  "{client} wants to access your found.as page with these permissions:",
                  { client: <strong>{clientHost}</strong> },
                )}
              </p>
              <ul className="help scope-list">
                {scopes.map((scope) => (
                  <li key={scope}>{scope}</li>
                ))}
              </ul>
            </>
          ) : (
            <p className="help">
              {tx("{client} wants to confirm you own this found.as page.", {
                client: <strong>{clientHost}</strong>,
              })}
            </p>
          )}
        </div>
        <form className="setup-form" onSubmit={approve}>
          {needsPassword && (
            <>
              <label className="field">
                <span>{t("Page password")}</span>
                <input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onInput={(e) =>
                    setPassword((e.target as HTMLInputElement).value)
                  }
                  placeholder={t("Your page password")}
                  autoFocus
                />
              </label>
              <label className="show-toggle">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) =>
                    setRemember((e.target as HTMLInputElement).checked)
                  }
                />
                <span>{t("Remember on this device")}</span>
              </label>
              {remember && (
                <p className="help warning-text">
                  {t(
                    "Saves this page's key in this browser so future sign-ins skip the password. Only on a device you trust.",
                  )}
                </p>
              )}
            </>
          )}
          {error && <p className="help error-text">{error}</p>}
          <div className="action-row">
            <button
              type="submit"
              disabled={phase === "submitting" || (needsPassword && !password)}
            >
              {phase === "submitting"
                ? t("Signing in…")
                : scopes.length
                  ? t("Allow access")
                  : t("Continue")}
            </button>
            <button
              type="button"
              className="secondary"
              onClick={deny}
              disabled={phase === "submitting"}
            >
              {t("Cancel")}
            </button>
          </div>
          <p className="help">
            {t(
              "Your password never leaves this device — it only signs the approval.",
            )}
          </p>
        </form>
      </main>
    </div>
  );
}
