import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { Signal, useSignal } from "@preact/signals";
import { marked } from "marked";
import fm from "front-matter";
import { sign, SignKeyPair } from "tweetnacl";
import { decode, encode } from "cbor-x";

const subtle = window.crypto.subtle;
const textEncoder = new TextEncoder();

enum Type {
  HTML_PAGE,
  MARKDOWN_PAGE,
  REDIR,
  BYTES,
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
  mime?: string;
  bytes?: Uint8Array;
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
${attrs["title"] ? `<title>${attrs["title"].replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</title>` : ""}
</head>
<body>${fragment}</body>
</html>`;
}

function PageEditor({ priv, pub }: { priv: Signal<Private>; pub: Public }) {
  const ifref = useRef<HTMLIFrameElement>(null);
  useEffect(() => {
    ifref.current?.contentWindow?.postMessage(pub.html, "*");
  }, [ifref.current, pub.html]);
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
      />
      {boolishSymbol(valid)}
    </>
  );
}

let postSingleton: AbortController | null = null;

async function post(body: any) {
  if (postSingleton && !postSingleton.signal.aborted) {
    postSingleton.abort();
  }
  postSingleton = new AbortController();
  return fetch("/api", {
    method: "POST",
    body: encode(body),
    signal: postSingleton.signal,
  });
}

async function updateData(
  keyPair: SignKeyPair,
  path: string,
  priv: Private,
  pub: Public,
): Promise<void> {
  const response = await post([
    1,
    keyPair.publicKey,
    sign(
      encode([new Date().getTime() / 1000, path, encode(priv), encode(pub)]),
      keyPair.secretKey,
    ),
  ]);
  if (!response.ok) {
    throw new Error(`${response.status} (${await response.text()})`);
  }
}

async function updatePw(
  keyPair: SignKeyPair,
  path: string,
  newPw: string,
): Promise<void> {
  const newKey = await deriveKP(path, newPw);
  const response = await post([
    3,
    keyPair.publicKey,
    sign(
      encode([new Date().getTime() / 1000, path, newKey.publicKey]),
      keyPair.secretKey,
    ),
  ]);
  if (!response.ok) {
    throw new Error(`${response.status} (${await response.text()})`);
  }
}

async function fetchData(keyPair: SignKeyPair, path: string): Promise<Private> {
  const response = await post([
    2,
    keyPair.publicKey,
    sign(encode([new Date().getTime() / 1000, path]), keyPair.secretKey),
  ]);
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

async function deriveKP(path: string, pw: string) {
  return sign.keyPair.fromSeed(
    new Uint8Array(
      await subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: textEncoder.encode(`found.as/${path}`),
          iterations: 100000,
        },
        await subtle.importKey("raw", textEncoder.encode(pw), "PBKDF2", false, [
          "deriveBits",
        ]),
        256,
      ),
    ),
  );
}

export function App() {
  const priv = useSignal<Private>({
    type: Type.REDIR,
    md: "",
    html: "",
    redir: "",
  });

  const [working, setWorking] = useState<boolean>(false);
  const [pw, setPw] = useState<string>("");
  const [newPw, setNewPw] = useState<string>("");
  const [path, setPath] = useState<string>(
    decodeURIComponent(window.location.pathname.substring(1)),
  );
  const [pathIsNew, setPathIsNew] = useState<boolean>(false);
  const [kp, setKP] = useState<SignKeyPair | null>(null);
  const [pwStatus, setPwStatus] = useState<boolean | undefined>(undefined);
  const [refreshTimeout, setRefreshTimeout] = useState<number | null>(null);
  const [file, setFile] = useState<File | undefined>(undefined);

  const pub = useMemo<Public | null>(() => {
    if (priv.value.type === Type.REDIR) {
      return { redir: priv.value.redir };
    }

    if (priv.value.type === Type.BYTES && file) {
      return null;
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
  }, [priv.value, file]);

  useEffect(() => {
    window.history.replaceState(null, "", `/${path}`);
    setWorking(true);
    (async () => {
      setKP(await deriveKP(path, pw));
    })()
      .catch((e) => {
        window.alert(e.message);
      })
      .finally(() => {
        setWorking(false);
      });
  }, [path, pw]);

  useEffect(() => {
    if (refreshTimeout) {
      clearTimeout(refreshTimeout);
    }
    if (!kp) {
      return;
    }
    setWorking(true);
    setRefreshTimeout(
      setTimeout(() => {
        fetchData(kp, path)
          .then((recvPriv) => {
            priv.value = recvPriv;
            setPwStatus(true);
            setPathIsNew(false);
          })
          .catch((e) => {
            if (e instanceof FourOFour) {
              setPwStatus(true);
              setPathIsNew(true);
            } else if (e instanceof FourXX) {
              setPwStatus(false);
            } else if (e.name !== "AbortError") {
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
        Hi!{" "}
        <span class="nbl">
          found<span class="sep">.</span>as
          <span class="sep">/</span>
          <input
            type="text"
            placeholder="path"
            maxlength={32}
            value={path || ""}
            onInput={(e) => {
              const current = (e.target as HTMLInputElement).value;
              setPath(current);
            }}
          />
          <button
            onClick={() =>
              navigator.clipboard.writeText(`https://found.as/${path}`)
            }
          >
            📋
          </button>
        </span>
        ,<br />
        updatable with{" "}
        <span class="nbl">
          <input
            type="password"
            placeholder="password"
            value={pw || ""}
            onInput={(e) => setPw((e.target as HTMLInputElement).value)}
          />
          {boolishSymbol(pwStatus)}
        </span>
        {pwStatus && !pathIsNew ? (
          <>
            {" "}
            (<button popovertarget="changePw">change</button>)
          </>
        ) : pwStatus && pw === "" ? (
          <> (so anyone can update)</>
        ) : null}
        ,<br />I serve{" "}
        <select
          value={priv.value.type}
          onChange={(e) => {
            priv.value = {
              ...priv.value,
              type: Number((e.target as HTMLOptionElement).value),
            };
          }}
        >
          <option name={String(Type.REDIR)} value={Type.REDIR}>
            a redirect
          </option>
          <option name={String(Type.MARKDOWN_PAGE)} value={Type.MARKDOWN_PAGE}>
            a markdown page
          </option>
          <option name={String(Type.HTML_PAGE)} value={Type.HTML_PAGE}>
            an HTML page
          </option>
          <option name={String(Type.BYTES)} value={Type.BYTES}>
            a file (max 1MB)
          </option>
        </select>
        {priv.value.type === Type.REDIR ? (
          <>
            {" "}
            <RedirectEditor priv={priv} />
          </>
        ) : priv.value.type === Type.BYTES ? (
          <>
            {" "}
            from{" "}
            <input
              type="file"
              onChange={(e) => {
                const target = e.target as HTMLInputElement;
                const file = target.files?.[0];
                if (!file) {
                  setFile(file);
                  return;
                }
                if (file.size > 1024 * 1024) {
                  window.alert("File too large (max 1MB)");
                  target.value = target.defaultValue;
                  return;
                }
                setFile(file);
              }}
            />
          </>
        ) : (
          <>:</>
        )}
      </h1>
      {(priv.value.type === Type.HTML_PAGE ||
        priv.value.type === Type.MARKDOWN_PAGE) &&
        pub !== null && <PageEditor priv={priv} pub={pub} />}
      <footer>
        <button
          disabled={
            working || !pwStatus || (priv.value.type === Type.BYTES && !file)
          }
          onClick={() => {
            if (!kp) {
              return;
            }
            setWorking(true);
            (pub !== null
              ? updateData(kp, path, priv.value, pub)
              : (async () =>
                  updateData(kp, path, priv.value, {
                    bytes: new Uint8Array(await file!.arrayBuffer()),
                    mime: file!.type,
                  }))()
            )
              .then(() => {
                setPathIsNew(false);
                window.open(`https://found.as/${path}`, "_blank");
              })
              .catch((e) => {
                window.alert(e.message);
              })
              .finally(() => {
                setWorking(false);
              });
          }}
        >
          now
        </button>
      </footer>
      <div popover="auto" id="changePw">
        <input
          type="password"
          placeholder="new password"
          value={newPw}
          onInput={(e) => setNewPw((e.target as HTMLInputElement).value)}
        />
        <button
          onClick={() => {
            if (!kp) {
              return;
            }
            setWorking(true);
            updatePw(kp, path, newPw)
              .then(() => {
                setPw(newPw);
                setNewPw("");
                document.getElementById("changePw")?.hidePopover();
              })
              .catch((e) => {
                window.alert(e.message);
              })
              .finally(() => {
                setWorking(false);
              });
          }}
        >
          change
        </button>
      </div>
    </main>
  );
}
