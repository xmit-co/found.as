import {
  DomainStatus,
  PendingDomain,
  customDomainStatus,
  listCustomDomains,
  mapCustomDomain,
  normalizeDomainInput,
  unmapCustomDomain,
} from "../api";
import { useEffect, useRef, useState } from "preact/hooks";
import { SignKeyPair } from "tweetnacl";
import { t, tx } from "../i18n";

export function DnsRow({ type, value }: { type: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <span>{type}</span>
      <code>{value}</code>
      <button
        type="button"
        className="dns-copy"
        aria-label={t("Copy {type} value", { type })}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          } catch {
            // clipboard blocked — the value is still selectable by hand
          }
        }}
      >
        {copied ? t("Copied ✓") : t("Copy")}
      </button>
    </div>
  );
}

export function DomainPopover({
  kp,
  path,
  shareDomain,
  setShareDomain,
  onError,
}: {
  kp: SignKeyPair;
  path: string;
  shareDomain: string | null;
  setShareDomain: (d: string | null) => void;
  onError: (message: string) => void;
}) {
  const [domains, setDomains] = useState<string[] | null>(null);
  const [statuses, setStatuses] = useState<Record<string, DomainStatus>>({});
  const [input, setInput] = useState("");
  const [pending, setPending] = useState<PendingDomain | null>(null);
  const [busy, setBusy] = useState(false);
  const [justConnected, setJustConnected] = useState("");
  const [lastStatus, setLastStatus] = useState<{
    domain: string;
    status: DomainStatus;
  } | null>(null);
  const checkNow = useRef<(() => void) | null>(null);

  const refresh = async () => {
    try {
      const list = await listCustomDomains(kp, path);
      setDomains(list);
      const next: Record<string, DomainStatus> = {};
      for (const domain of list) {
        try {
          next[domain] = await customDomainStatus(kp, path, domain);
        } catch {
          // shown as unknown until the next refresh
        }
      }
      setStatuses(next);
    } catch (e) {
      onError((e as Error).message);
    }
  };

  useEffect(() => {
    const panel = document.getElementById("customDomain");
    if (!panel) {
      return;
    }
    const onToggle = (e: Event) => {
      if ((e as ToggleEvent).newState !== "open") {
        return;
      }
      if (domains === null) {
        refresh();
      }
    };
    panel.addEventListener("toggle", onToggle);
    return () => panel.removeEventListener("toggle", onToggle);
  }, [domains, kp, path]);

  useEffect(() => {
    if (!pending) {
      return;
    }
    const domain = pending.domain;
    let cancelled = false;
    const tick = async () => {
      try {
        const status = await customDomainStatus(kp, path, domain);
        if (cancelled) {
          return;
        }
        setLastStatus({ domain, status });
        if (status.conflict) {
          setPending(null);
          onError(t("This domain is already connected to another page."));
          return;
        }
        if (status.certPaused) {
          setPending(null);
          onError(
            t(
              "We couldn't secure {domain} after repeated attempts. Remove it, check your DNS records, and try again.",
              { domain },
            ),
          );
          refresh();
          return;
        }
        if (status.mapped && status.cert) {
          setPending(null);
          setJustConnected(domain);
          refresh();
          return;
        }
        if (!status.mapped && status.bound && status.reachable) {
          await mapCustomDomain(kp, path, domain);
          if (!cancelled) {
            setPending({ ...pending, domain, state: "securing" });
          }
          return;
        }
        if (status.mapped && pending.state !== "securing") {
          setPending({ ...pending, domain, state: "securing" });
        }
      } catch {
        // transient — checked again on the next tick
      }
    };
    checkNow.current = tick;
    tick();
    // While waiting on DNS, poll slower than the server's ~10s reachability
    // probe so checks never overlap; once securing, a cert usually lands in
    // seconds, so check more eagerly.
    const interval = window.setInterval(
      tick,
      pending.state === "securing" ? 4000 : 15000,
    );
    return () => {
      cancelled = true;
      checkNow.current = null;
      window.clearInterval(interval);
    };
  }, [pending?.domain, pending?.state, kp, path]);

  const connect = async () => {
    const domain = normalizeDomainInput(input);
    if (!domain) {
      onError(t("Enter a domain like yourname.com."));
      return;
    }
    setBusy(true);
    try {
      const status = await customDomainStatus(kp, path, domain);
      if (status.conflict) {
        onError(t("This domain is already connected to another page."));
        return;
      }
      setJustConnected("");
      setInput("");
      setLastStatus({ domain, status });
      if (status.mapped && status.cert) {
        await refresh();
        return;
      }
      const base = {
        domain,
        target: status.target,
        label: status.label,
        isApex: status.apex,
      };
      if (status.mapped || (status.bound && status.reachable)) {
        if (!status.mapped) {
          await mapCustomDomain(kp, path, domain);
        }
        setPending({ ...base, state: "securing" });
      } else {
        setPending({ ...base, state: "waiting" });
      }
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (domain: string) => {
    setBusy(true);
    try {
      await unmapCustomDomain(kp, path, domain);
      if (pending?.domain === domain) {
        setPending(null);
      }
      if (justConnected === domain) {
        setJustConnected("");
      }
      if (shareDomain === domain) {
        setShareDomain(null);
      }
      await refresh();
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const listed = (domains ?? []).filter((d) => d !== pending?.domain);
  const liveDomains = (domains ?? []).filter((d) => statuses[d]?.cert);

  const cnameInstructions = (p: PendingDomain) => (
    <>
      <p>
        {tx(
          "Sign in wherever you manage {domain}'s DNS — usually where you bought it — and add a CNAME record:",
          { domain: <strong>{p.domain}</strong> },
        )}
      </p>
      <div className="dns-records">
        <DnsRow type="CNAME" value={p.target} />
      </div>
      <p className="help">
        {tx(
          "One CNAME on {domain} pointing to the address above. It connects the domain and proves it's yours in a single record.",
          { domain: <code>{p.domain}</code> },
        )}
      </p>
    </>
  );

  const apexInstructions = (p: PendingDomain) => (
    <>
      <p>
        {tx(
          "A bare domain can't use a CNAME, so it takes two steps. First, if your DNS provider offers an ALIAS or ANAME record (or CNAME flattening), point {domain} at this name — we keep it aimed at our servers, so it never needs updating:",
          { domain: <strong>{p.domain}</strong> },
        )}
      </p>
      <div className="dns-records">
        <DnsRow type="ALIAS" value={p.target} />
      </div>
      <p className="help">
        {t("Then add this record so we know the domain is yours:")}
      </p>
      <div className="dns-records">
        <DnsRow type="TXT" value={`found=${p.label}`} />
      </div>
      <p className="help">
        {tx(
          "No ALIAS support? Use a subdomain like {www} instead — it takes a plain CNAME.",
          {
            www: <code>www.{p.domain}</code>,
          },
        )}
      </p>
    </>
  );

  // Turn the separate bound/reachable signals into a plain-language "you're
  // halfway" nudge, so a bare-domain owner who added the addresses but skipped
  // the TXT (or vice versa) knows exactly which record is still missing.
  const diagnostic = (p: PendingDomain) => {
    if (!lastStatus || lastStatus.domain !== p.domain) {
      return null;
    }
    const s = lastStatus.status;
    if (s.reachable && !s.bound) {
      return (
        <p className="help domain-progress" aria-live="polite">
          {t(
            "✓ {domain} is reaching us. Now add the record that proves it's yours — the {record} below.",
            {
              domain: p.domain,
              record: p.isApex ? t("TXT record") : "CNAME",
            },
          )}
        </p>
      );
    }
    if (s.bound && !s.reachable) {
      return (
        <p className="help domain-progress" aria-live="polite">
          {t(
            "✓ We can see your proof record — now waiting for {domain} to route to us, usually just the DNS change spreading.",
            { domain: p.domain },
          )}
        </p>
      );
    }
    return null;
  };

  const pendingActions = (p: PendingDomain) => (
    <div className="popover-actions domain-actions">
      <button
        type="button"
        disabled={busy}
        onClick={() => checkNow.current?.()}
      >
        {t("Check now")}
      </button>
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() => remove(p.domain)}
      >
        {t("Cancel")}
      </button>
    </div>
  );

  return (
    <div
      popover="auto"
      id="customDomain"
      className="popover-panel domain-popover"
    >
      <div className="popover-heading">
        <h2>{t("Manage domains")}</h2>
        <button
          type="button"
          className="icon-button"
          aria-label={t("Close")}
          onClick={() => document.getElementById("customDomain")?.hidePopover()}
        >
          <span aria-hidden="true">×</span>
        </button>
      </div>
      <p className="help">
        {t(
          "A domain you own can show this page. Your found.as address keeps working — the domain is an extra way in, and you can remove it anytime.",
        )}
      </p>
      {domains === null ? (
        <p className="help">{t("Loading…")}</p>
      ) : (
        <>
          {listed.map((domain) => {
            const status = statuses[domain];
            return (
              <div className="domain-row" key={domain}>
                <a href={`https://${domain}/`} target="_blank" rel="noreferrer">
                  {domain}
                </a>
                <span className="help">
                  {status === undefined
                    ? ""
                    : status.cert
                      ? t("live")
                      : status.certPaused
                        ? t("needs attention")
                        : t("securing…")}
                </span>
                <button
                  type="button"
                  className="secondary"
                  disabled={busy}
                  onClick={() => remove(domain)}
                >
                  {t("Remove")}
                </button>
              </div>
            );
          })}
          {justConnected && (
            <p className="help" aria-live="polite">
              🎉{" "}
              {tx("{link} is live.", {
                link: (
                  <a
                    href={`https://${justConnected}/`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    https://{justConnected}
                  </a>
                ),
              })}
            </p>
          )}
          {liveDomains.length > 0 && (
            <fieldset className="main-address">
              <legend>{t("Main address")}</legend>
              <p className="help">
                {t(
                  "The address featured on your QR code, printables and email signature. Your page stays reachable at every address either way.",
                )}
              </p>
              <label className="main-address-option">
                <input
                  type="radio"
                  name="main-address"
                  checked={shareDomain === null}
                  onChange={() => setShareDomain(null)}
                />
                <span>found.as/{path}</span>
              </label>
              {liveDomains.map((domain) => (
                <label className="main-address-option" key={domain}>
                  <input
                    type="radio"
                    name="main-address"
                    checked={shareDomain === domain}
                    onChange={() => setShareDomain(domain)}
                  />
                  <span>{domain}</span>
                </label>
              ))}
            </fieldset>
          )}
          {pending ? (
            <div className="domain-pending">
              {pending.state === "waiting" ? (
                <>
                  <p>
                    {tx("{domain} isn't connected yet.", {
                      domain: <strong>{pending.domain}</strong>,
                    })}
                  </p>
                  {diagnostic(pending)}
                  {pending.isApex ? (
                    <>
                      {apexInstructions(pending)}
                      <details className="domain-apex">
                        <summary>
                          {t("On a subdomain instead (like www.{domain})?", {
                            domain: pending.domain,
                          })}
                        </summary>
                        {cnameInstructions(pending)}
                      </details>
                    </>
                  ) : (
                    <>
                      {cnameInstructions(pending)}
                      <details className="domain-apex">
                        <summary>
                          {t("Using a bare domain like example.com?")}
                        </summary>
                        {apexInstructions(pending)}
                      </details>
                    </>
                  )}
                  <p className="help" aria-live="polite">
                    {t(
                      "We check every few seconds — you can close this window and come back later.",
                    )}
                  </p>
                  {pendingActions(pending)}
                </>
              ) : (
                <>
                  <p aria-live="polite">
                    {tx(
                      "Found it! Securing {domain} — this usually takes under a minute…",
                      { domain: <strong>{pending.domain}</strong> },
                    )}
                  </p>
                  {pendingActions(pending)}
                </>
              )}
            </div>
          ) : (
            <>
              <label className="field stack">
                <span>{t("Domain you own")}</span>
                <input
                  type="text"
                  value={input}
                  placeholder={t("yourname.com")}
                  onInput={(e) =>
                    setInput((e.target as HTMLInputElement).value)
                  }
                />
              </label>
              <div className="popover-actions">
                <button
                  type="button"
                  disabled={busy || !input.trim()}
                  onClick={connect}
                >
                  {t("Connect")}
                </button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
