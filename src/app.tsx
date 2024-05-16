import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { Signal, useSignal } from "@preact/signals";
import { marked } from "marked";
import fm from "front-matter";
import { sign, SignKeyPair } from "tweetnacl";
import { decode, encode } from "cbor-x";

const subtle = window.crypto.subtle;

enum Type {
  HTML_PAGE,
  MARKDOWN_PAGE,
  REDIR,
}

interface Private {
  type: Type;
  md: string;
  html: string;
  redir: string;
}

interface Public {
  redir?: string;
  html?: string;
}

class FourOFour extends Error {
  constructor(message: string) {
    super(message);
  }
}

class FourXX extends Error {
  constructor(message: string) {
    super(message);
  }
}

function intoDoc(fragment: string, attrs: Record<string, any>) {
  return `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<style>:root { color-scheme: dark light; }</style>
${attrs["title"] ? `<title>${attrs["title"]}</title>` : ""}
</head>
<body>${fragment}</body>
</html>`;
}

function PageEditor({ priv, pub }: { priv: Signal<Private>; pub: Public }) {
  const ifref = useRef<HTMLIFrameElement>(null);
  if (ifref.current !== null) {
    ifref.current.contentWindow?.postMessage(pub.html, "*");
  }
  return (
    <div className="edit-and-preview">
      <textarea
        placeholder={`Start writing ${priv.value.type === Type.HTML_PAGE ? "HTML" : "GitHub-flavored markdown, optionally prefixed with:\n---\ntitle: Page title\n---\n"}`}
        className="code"
        value={
          priv.value.type === Type.HTML_PAGE ? priv.value.html : priv.value.md
        }
        onInput={(e) => {
          if (priv.value.type === Type.HTML_PAGE) {
            priv.value = {
              ...priv.value,
              html: (e.target as HTMLTextAreaElement).value,
            };
          } else {
            priv.value = {
              ...priv.value,
              md: (e.target as HTMLTextAreaElement).value,
            };
          }
        }}
      ></textarea>
      <iframe
        class="preview"
        ref={ifref}
        srcdoc={`<html><head><script>window.addEventListener('message', (e) => document.documentElement.innerHTML = e.data)</script></head><body></body></html>`}
      ></iframe>
    </div>
  );
}

function RedirectEditor({ priv }: { priv: Signal<Private> }) {
  const valid = useMemo(
    () => URL.canParse(priv.value.redir),
    [priv.value.redir],
  );
  return (
    <>
      to{" "}
      <input
        type="url"
        value={priv.value.redir}
        onInput={(e) => {
          priv.value = {
            ...priv.value,
            redir: (e.target as HTMLInputElement).value,
          };
        }}
      />&nbsp;{boolishSymbol(valid)}
    </>
  );
}

async function post(body: any) {
  return fetch("/api", {
    method: "POST",
    body: encode(body),
  });
}

async function updateData(
  keyPair: SignKeyPair,
  path: string,
  priv: Private,
  pub: Public,
): Promise<void> {
  const body = [
    1,
    keyPair.publicKey,
    sign(
      encode([new Date().getTime() / 1000, path, encode(priv), encode(pub)]),
      keyPair.secretKey,
    ),
  ];
  const response = await post(body);
  if (!response.ok) {
    throw new Error(`${response.status} (${await response.text()})`);
  }
}

async function fetchData(keyPair: SignKeyPair, path: string): Promise<Private> {
  const body = [
    2,
    keyPair.publicKey,
    sign(encode([new Date().getTime() / 1000, path]), keyPair.secretKey),
  ];
  const response = await post(body);
  if (!response.ok) {
    if (response.status === 404) {
      throw new FourOFour(await response.text());
    }
    if (response.status >= 400 && response.status < 500) {
      throw new FourXX(await response.text());
    }
    throw new Error(`${response.status} (${await response.text()})`);
  }
  return decode(new Uint8Array(await response.arrayBuffer()));
}

function boolishSymbol(b: boolean | undefined): string {
  return b === undefined ? "❓" : b ? "✅" : "❌";
}

export function App() {
  const priv = useSignal<Private>({
    type: Type.MARKDOWN_PAGE,
    md: "",
    html: "",
    redir: "",
  });

  const [working, setWorking] = useState<boolean>(false);
  const [pw, setPw] = useState<string>("");
  const [path, setPath] = useState<string>("");
  const [kp, setKP] = useState<SignKeyPair | null>(null);
  const [pwStatus, setPwStatus] = useState<boolean | undefined>(undefined);
  const [pathStatus, setPathStatus] = useState<boolean>(true);
  const [refreshTimeout, setRefreshTimeout] = useState<number | null>(null);

  const pub = useMemo<Public>(() => {
    if (priv.value.type === Type.REDIR) {
      return { redir: priv.value.redir };
    }

    let attrs: Record<string, any> = {};

    function preprocess(md: string): string {
      const { attributes, body } = fm(md);
      attrs = attributes as Record<string, any>;
      return body;
    }

    return {
      html:
        priv.value.type === Type.HTML_PAGE
          ? priv.value.html
          : intoDoc(
              marked.parse(priv.value.md, {
                pedantic: false,
                gfm: true,
                breaks: true,
                hooks: {
                  options: {},
                  preprocess,
                  postprocess: (html) => html,
                  processAllTokens: (x) => x,
                },
              }) as string,
              attrs,
            ),
    };
  }, [priv.value]);

  useEffect(() => {
    setWorking(true);
    (async () => {
      const key = await subtle.importKey(
        "raw",
        new TextEncoder().encode(pw || ""),
        "PBKDF2",
        false,
        ["deriveBits"],
      );
      const bits = await subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: new TextEncoder().encode("found.as"),
          iterations: 100000,
        },
        key,
        256,
      );
      setKP(sign.keyPair.fromSeed(new Uint8Array(bits)));
    })()
      .catch((e) => {
        window.alert(e.message);
      })
      .finally(() => {
        setWorking(false);
      });
  }, [pw]);

  useEffect(() => {
    if (refreshTimeout) {
      clearTimeout(refreshTimeout);
    }
    if (!pathStatus || !kp) {
      return;
    }
    setWorking(true);
    setRefreshTimeout(
      setTimeout(() => {
        fetchData(kp, path)
          .then((recvPriv) => {
            priv.value = recvPriv;
            setPwStatus(true);
          })
          .catch((e) => {
            if (e instanceof FourOFour) {
              setPwStatus(true);
            } else if (e instanceof FourXX) {
              setPwStatus(false);
            } else {
              window.alert(e.message);
            }
          })
          .finally(() => {
            setWorking(false);
          });
      }, 200),
    );
    return () => {
      if (refreshTimeout) clearTimeout(refreshTimeout);
    };
  }, [path, kp]);

  return (
    <main>
      <h1>
        <span class="nbl">
          Hi! found<span class="sep">.</span>as
          <span class="sep">/</span>
          <input
            type="text"
            placeholder="path"
            maxlength={32}
            value={path || ""}
            onInput={(e) => {
              const current = (e.target as HTMLInputElement).value;
              setPath(current);
              try {
                const url = new URL(`https://found.as/${current}`);
                setPathStatus(url.pathname === `/${current}`);
              } catch {
                setPathStatus(false);
              }
            }}
          />
          &nbsp;{boolishSymbol(pathStatus)}
        </span>
        ,<br />
        write-protected by{" "}
        <input
          type="password"
          placeholder="password"
          value={pw || ""}
          onInput={(e) => setPw((e.target as HTMLInputElement).value)}
        />
        &nbsp;{boolishSymbol(pwStatus)},<br />I serve{" "}
        <select
          value={priv.value.type}
          onChange={(e) => {
            priv.value = {
              ...priv.value,
              type: Number((e.target as HTMLOptionElement).value),
            };
          }}
        >
          <option name={String(Type.MARKDOWN_PAGE)} value={Type.MARKDOWN_PAGE}>
            a markdown page
          </option>
          <option name={String(Type.HTML_PAGE)} value={Type.HTML_PAGE}>
            an HTML page
          </option>
          <option name={String(Type.REDIR)} value={Type.REDIR}>
            a redirect
          </option>
        </select>
        {priv.value.type === Type.REDIR ? (
          <>
            {" "}
            <RedirectEditor priv={priv} />
          </>
        ) : (
          <>:</>
        )}
      </h1>
      {priv.value.type !== Type.REDIR && <PageEditor priv={priv} pub={pub} />}
      <footer>
        <button
          disabled={working || !pathStatus || !pwStatus}
          onClick={() => {
            if (!kp) {
              return;
            }
            updateData(kp, path, priv.value, pub)
              .then(() => {
                window.open(`https://found.as/${path}`, "_blank");
              })
              .catch((e) => {
                window.alert(e.message);
              });
          }}
        >
          now
        </button>
      </footer>
    </main>
  );
}
