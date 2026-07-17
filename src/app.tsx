import {
  deletePage,
  deriveKP,
  fetchData,
  renamePage,
  updateData,
  updatePw,
} from "./api";
import { exportBackupZip, readPrivFromBackup } from "./backup";
import { DomainPopover } from "./components/DomainPopover";
import { EmailSignaturePopover } from "./components/EmailSignaturePopover";
import {
  FileEditor,
  LinkTreeEditor,
  PageEditor,
  RedirectEditor,
} from "./components/LinkEditors";
import { QrCode } from "./components/QrCode";
import {
  BuilderModePicker,
  SetupPanel,
  modeSummary,
} from "./components/SetupPanel";
import { bakeTreeImages, dataUrlToSub, subVersion } from "./image";
import {
  createDefaultPrivate,
  ensureLinkTree,
  linkTreeErrors,
  linkTreeHasPublishableContent,
  normalizeLink,
  normalizeUrl,
} from "./linktree";
import { renderOgImage } from "./og";
import { downloadQrPng } from "./qr";
import {
  intoDoc,
  linkTreeProfile,
  linkTreeToHtml,
  printablesHtml,
  recoveryKitHtml,
} from "./render";
import {
  RememberedPage,
  forgetPage,
  fromBase64Url,
  loadMainAddress,
  loadRemembered,
  rememberPage,
  rememberedKeyPair,
  saveMainAddress,
  toBase64Url,
} from "./storage";
import { BuilderMode, FourOFour, FourXX, Private, Public, Type } from "./types";
import { downloadFile, encodePath, pageSubUrl, publicPageUrl } from "./util";
import { buildVcard } from "./vcard";
import { useSignal } from "@preact/signals";
import fm from "front-matter";
import { marked } from "marked";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { SignKeyPair, sign } from "tweetnacl";

// A recovery link carries the page's Ed25519 seed (32 bytes) in the URL
// fragment: https://be.found.as/<page>#<seed>. The fragment never reaches the
// server, so it opens the editor without the password.
function hashSeed(): Uint8Array | null {
  const raw = window.location.hash.replace(/^#/, "").trim();
  if (!raw) return null;
  try {
    const bytes = fromBase64Url(raw);
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

export function App() {
  const priv = useSignal<Private>(createDefaultPrivate());
  const fetchSeq = useRef(0);
  // Set just before a rename moves `path`, so the path-change effect keeps the
  // editor open instead of bouncing back to the unlock screen.
  const renamingRef = useRef(false);

  const [working, setWorking] = useState<boolean>(false);
  const [pw, setPw] = useState<string>("");
  const [newPw, setNewPw] = useState<string>("");
  const [path, setPath] = useState<string>(
    decodeURIComponent(window.location.pathname.substring(1)),
  );
  const [pathIsNew, setPathIsNew] = useState<boolean>(false);
  // A recovery link (#seed in the URL) opens the editor straight away.
  const seedRef = useRef<Uint8Array | null>(hashSeed());
  const openedFromLink = useRef<boolean>(seedRef.current !== null);
  // The only path a device-remembered key may open without confirmation: the
  // one from the URL on arrival, or one the visitor explicitly picks from the
  // remembered list. Typing an address into the field never auto-opens it.
  const autoOpenPath = useRef<string>(
    decodeURIComponent(window.location.pathname.substring(1)).trim(),
  );
  // Set when the visitor picks a remembered page from the list, so even the
  // root ("") opens on demand — while a bare landing at be.found.as/ still
  // shows the entry screen rather than auto-opening a remembered root.
  const explicitOpen = useRef<boolean>(false);
  const [setupComplete, setSetupComplete] = useState<boolean>(
    () => seedRef.current !== null,
  );
  const [kp, setKP] = useState<SignKeyPair | null>(() =>
    seedRef.current ? sign.keyPair.fromSeed(seedRef.current) : null,
  );
  const [remembered, setRemembered] =
    useState<RememberedPage[]>(loadRemembered);
  const [remember, setRemember] = useState<boolean>(false);
  const [pwStatus, setPwStatus] = useState<boolean | undefined>(undefined);
  const [file, setFile] = useState<File | undefined>(undefined);
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [lastAdvancedType, setLastAdvancedType] = useState<Type>(Type.REDIR);
  const [toast, setToast] = useState<string>("");
  const [copied, setCopied] = useState<boolean>(false);
  const [shareOpen, setShareOpen] = useState<boolean>(false);
  const [justPublished, setJustPublished] = useState<boolean>(false);
  const [qrMode, setQrMode] = useState<"link" | "vcard">("link");
  const [shareDomain, setShareDomain] = useState<string | null>(null);
  const [renameTo, setRenameTo] = useState<string>("");
  const [deleteConfirm, setDeleteConfirm] = useState<string>("");

  const showError = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 6000);
  };

  // Transient confirmation in the publish bar; clears itself.
  const statusTimer = useRef(0);
  const flashStatus = (message: string) => {
    setStatusMessage(message);
    window.clearTimeout(statusTimer.current);
    statusTimer.current = window.setTimeout(() => setStatusMessage(""), 8000);
  };

  const closeMenu = () => document.getElementById("topbarMenu")?.hidePopover();

  const builderMode: BuilderMode =
    priv.value.type === Type.LINK_TREE ? "contact" : "advanced";
  const advancedType =
    priv.value.type === Type.LINK_TREE ? lastAdvancedType : priv.value.type;
  const tree = ensureLinkTree(priv.value.linkTree);
  const treeErrors =
    priv.value.type === Type.LINK_TREE ? linkTreeErrors(tree) : [];
  const validationErrors = useMemo(() => {
    if (priv.value.type === Type.LINK_TREE) {
      return treeErrors;
    }
    if (priv.value.type === Type.REDIR) {
      const target = normalizeUrl(priv.value.redir);
      if (!target) {
        return ["Enter a redirect destination before publishing."];
      }
      if (!URL.canParse(target)) {
        return ["Enter a valid redirect destination before publishing."];
      }
    }
    return [];
  }, [priv.value.type, priv.value.redir, treeErrors]);

  const pub = useMemo<Public | null>(() => {
    if (priv.value.type === Type.LINK_TREE) {
      return {
        html: linkTreeToHtml(
          ensureLinkTree(priv.value.linkTree),
          publicPageUrl(path.trim()),
        ),
      };
    }

    if (priv.value.type === Type.REDIR) {
      return { redir: normalizeUrl(priv.value.redir) };
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
  }, [priv.value, file, path]);
  const url = publicPageUrl(path.trim());
  // Share artifacts (QR, printables, signature, copy/share) feature the chosen
  // address — a connected custom domain if one is picked, otherwise found.as.
  // The canonical found.as URL stays baked into the published page itself.
  const shareUrl = shareDomain ? `https://${shareDomain}/` : url;
  // Address without scheme, for display (the QR pill in the generated preview).
  const shareDisplay = shareDomain ?? `found.as/${path.trim()}`;
  const renameDiscouraged =
    renameTo.trim() !== "" && /[^a-z0-9/-]/.test(renameTo.trim());
  const qrVcard =
    priv.value.type === Type.LINK_TREE
      ? buildVcard(tree, shareUrl, false)
      : null;
  const signatureAvailable =
    priv.value.type === Type.LINK_TREE &&
    Boolean(tree.displayName.trim() || path.trim());
  const wideEditor =
    priv.value.type === Type.HTML_PAGE ||
    priv.value.type === Type.MARKDOWN_PAGE;
  const contactNeedsContent =
    priv.value.type === Type.LINK_TREE && !linkTreeHasPublishableContent(tree);
  const canPublish =
    !working &&
    pwStatus === true &&
    (priv.value.type !== Type.BYTES || Boolean(file)) &&
    !contactNeedsContent &&
    validationErrors.length === 0;

  useEffect(() => {
    // Drop the #seed from the address bar so the key doesn't linger there.
    window.history.replaceState(null, "", path ? `/${encodePath(path)}` : "/");
    setRemember(loadRemembered().some((r) => r.path === path.trim()));
    if (openedFromLink.current) {
      // Opened from a recovery link: kp is already set from the #seed. Remember
      // it on this device so reloads work, and stay in the editor.
      openedFromLink.current = false;
      if (seedRef.current) {
        rememberPage(path.trim(), sign.keyPair.fromSeed(seedRef.current));
        setRemembered(loadRemembered());
        setRemember(true);
      }
      return;
    }
    if (renamingRef.current) {
      // A rename just moved the page; the new key derives from the same
      // password, so stay in the editor rather than re-prompting.
      renamingRef.current = false;
      return;
    }
    setSetupComplete(false);
    setStatusMessage("");
  }, [path]);

  useEffect(() => {
    let cancelled = false;
    // With no password typed, open straight from a key remembered on this
    // device, skipping the unlock screen — but only for a path arrived at by
    // URL or picked from the remembered list, never one just typed in (that
    // would log in mid-keystroke, without confirmation). The root ("") only
    // auto-opens when explicitly picked, so be.found.as/ stays the entry screen.
    if (
      pw === "" &&
      path.trim() === autoOpenPath.current &&
      (path.trim() !== "" || explicitOpen.current)
    ) {
      const saved = rememberedKeyPair(path.trim());
      if (saved) {
        explicitOpen.current = false;
        setKP(saved);
        setRemember(true);
        setSetupComplete(true);
        return;
      }
    }
    setWorking(true);
    deriveKP(path, pw)
      .then((keyPair) => {
        if (!cancelled) {
          setKP(keyPair);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          showError(e.message);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setWorking(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [path, pw]);

  // The featured address (found.as or a connected custom domain) is chosen in
  // the Custom domains popover and drives the QR code, printables, signature,
  // heading and generated preview. Load this page's saved choice.
  useEffect(() => {
    setShareDomain(loadMainAddress(path.trim()));
  }, [path]);

  const chooseMainAddress = (d: string | null) => {
    setShareDomain(d);
    saveMainAddress(path.trim(), d);
  };

  useEffect(() => {
    const currentFetch = ++fetchSeq.current;
    if (!kp) {
      return;
    }

    setWorking(true);
    const timeout = window.setTimeout(() => {
      fetchData(kp, path)
        .then((recvPriv) => {
          if (fetchSeq.current !== currentFetch) return;
          priv.value = recvPriv;
          setPwStatus(true);
          setPathIsNew(false);
        })
        .catch((e) => {
          if (fetchSeq.current !== currentFetch) return;
          if (e instanceof FourOFour) {
            priv.value = createDefaultPrivate();
            setPwStatus(true);
            setPathIsNew(true);
          } else if (e instanceof FourXX) {
            setPwStatus(false);
            setPathIsNew(false);
          } else if (e.name !== "AbortError") {
            showError(e.message);
          }
        })
        .finally(() => {
          if (fetchSeq.current === currentFetch) {
            setWorking(false);
          }
        });
    }, 200);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [path, kp]);

  useEffect(() => {
    if (priv.value.type !== Type.LINK_TREE) {
      setLastAdvancedType(priv.value.type);
    }
  }, [priv.value.type]);

  const setType = (type: Type) => {
    if (type !== Type.LINK_TREE) {
      setLastAdvancedType(type);
    }
    priv.value = {
      ...priv.value,
      type,
      linkTree:
        type === Type.LINK_TREE
          ? ensureLinkTree(priv.value.linkTree)
          : priv.value.linkTree,
    };
    setStatusMessage("");
  };

  const setBuilderMode = (mode: BuilderMode) => {
    setType(mode === "contact" ? Type.LINK_TREE : advancedType);
  };

  const copyPublicUrl = () => {
    navigator.clipboard
      .writeText(shareUrl)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1800);
      })
      .catch((e) => showError(e.message));
  };

  const canShare = typeof navigator.share === "function";

  const sharePublicUrl = () => {
    if (canShare) {
      navigator.share({ url: shareUrl }).catch(() => {});
    } else {
      copyPublicUrl();
    }
  };

  const vcardQrShown = qrMode === "vcard" && Boolean(qrVcard);

  const openPrintables = () => {
    const win = window.open("", "_blank");
    if (!win) {
      showError("Allow pop-ups to open the print page.");
      return;
    }
    win.document.write(printablesHtml(tree, shareUrl, shareDisplay));
    win.document.close();
  };

  // The recovery link carries this page's Ed25519 seed in the URL fragment, so
  // it opens the editor with no password — the key itself is the credential.
  const recoveryUrl = (keyPair: SignKeyPair) =>
    `https://be.found.as/${encodePath(path.trim())}#${toBase64Url(
      keyPair.secretKey.slice(0, 32),
    )}`;

  const saveRecoveryKit = () => {
    if (!kp) return;
    const slug = path.trim().replace(/\//g, "-") || "found-as";
    downloadFile(
      `${slug}-recovery-kit.html`,
      new Blob([recoveryKitHtml(path.trim(), url, recoveryUrl(kp))], {
        type: "text/html",
      }),
    );
  };

  const saveQr = () => {
    const slug = path.trim().replace(/\//g, "-") || "found-as";
    try {
      if (vcardQrShown) {
        downloadQrPng(qrVcard!, `${slug}-contact-qr.png`);
      } else {
        downloadQrPng(shareUrl, `${slug}-found-as-qr.png`);
      }
    } catch (e) {
      showError((e as Error).message);
    }
  };

  // The page's private value with link hrefs normalized — what gets stored and
  // exported.
  const normalizedPrivateValue = (): Private =>
    priv.value.type === Type.LINK_TREE
      ? {
          ...priv.value,
          linkTree: {
            ...tree,
            links: tree.links.map((link) => ({
              ...link,
              href: normalizeLink(link).href,
            })),
          },
        }
      : priv.value;

  // Build the published record (pub) from a private value — baking image crops,
  // rendering the OG image, and collecting subresources. Shared by publish and
  // export so both produce identical output.
  const buildPubToSend = async (privateValue: Private): Promise<Public> => {
    if (privateValue.type !== Type.LINK_TREE) {
      if (pub === null) {
        return file
          ? { bytes: new Uint8Array(await file.arrayBuffer()), mime: file.type }
          : {};
      }
      return pub;
    }
    // Publish the baked crops (the actual pixels), not the source + CSS — the
    // untouched source stays in `priv` for re-cropping. Fall back to the source
    // if baking fails so a publish never gets blocked.
    let publishTree = ensureLinkTree(privateValue.linkTree);
    try {
      publishTree = await bakeTreeImages(publishTree);
    } catch {
      // keep source images
    }
    // The preview image rides the page's pub record as the `og` subresource,
    // served at <path>/og — one atomic publish. Either the automatic render or
    // the uploaded custom image.
    let ogUrl: string | undefined;
    let subs: Public["subs"];
    if (tree.social?.autoImage ?? true) {
      try {
        const bytes = await renderOgImage(publishTree, shareDisplay);
        if (bytes) {
          subs = { og: { mime: "image/png", bytes } };
          ogUrl = `${publicPageUrl(path.trim())}/og?v=${await subVersion(bytes)}`;
        }
      } catch {
        showError(
          "Couldn't render the social preview image — publishing the page without it.",
        );
      }
    } else {
      const custom = tree.social?.customImage
        ? dataUrlToSub(tree.social.customImage)
        : null;
      if (custom) {
        subs = { og: custom };
        ogUrl = `${publicPageUrl(path.trim())}/og?v=${await subVersion(custom.bytes)}`;
      }
    }
    // Custom background: serve the upload as-is, plus the custom dark image if
    // one was chosen. The lighten/darken treatments are CSS overlays in the
    // page, so no variant needs baking here.
    let bgLightSubUrl: string | undefined;
    let bgDarkSubUrl: string | undefined;
    if (publishTree.background === "image" && publishTree.bgUrl) {
      try {
        const lightSub = dataUrlToSub(publishTree.bgUrl);
        if (lightSub) {
          subs = { ...(subs ?? {}), "bg-light": lightSub };
          bgLightSubUrl = pageSubUrl(
            path.trim(),
            "bg-light",
            await subVersion(lightSub.bytes),
          );
          const darkSub = publishTree.bgDarkUrl
            ? dataUrlToSub(publishTree.bgDarkUrl)
            : null;
          if (darkSub) {
            subs = { ...(subs ?? {}), "bg-dark": darkSub };
            bgDarkSubUrl = pageSubUrl(
              path.trim(),
              "bg-dark",
              await subVersion(darkSub.bytes),
            );
          }
        }
      } catch {
        // publish without the custom background rather than block
      }
    }
    // Avatar and cover ride the pub record as the `avatar` and `cover` subs,
    // referenced by URL from the page, instead of data: URLs inlined in the
    // HTML. External image URLs pass through untouched.
    let avatarSubUrl: string | undefined;
    let avatarAbsUrl: string | undefined;
    let coverSubUrl: string | undefined;
    const avatarSub = publishTree.avatarUrl
      ? dataUrlToSub(publishTree.avatarUrl)
      : null;
    if (avatarSub) {
      subs = { ...(subs ?? {}), avatar: avatarSub };
      const v = await subVersion(avatarSub.bytes);
      avatarSubUrl = pageSubUrl(path.trim(), "avatar", v);
      avatarAbsUrl = `${publicPageUrl(path.trim())}/avatar?v=${v}`;
    }
    const coverSub = publishTree.coverUrl
      ? dataUrlToSub(publishTree.coverUrl)
      : null;
    if (coverSub) {
      subs = { ...(subs ?? {}), cover: coverSub };
      coverSubUrl = pageSubUrl(
        path.trim(),
        "cover",
        await subVersion(coverSub.bytes),
      );
    }
    const pubToSend: Public = {
      html: linkTreeToHtml(
        publishTree,
        url,
        ogUrl,
        bgLightSubUrl,
        bgDarkSubUrl,
        avatarSubUrl,
        coverSubUrl,
      ),
    };
    if (subs) {
      pubToSend.subs = subs;
    }
    // Structured profile for the IndieAuth profile/email scopes. The photo
    // points at the avatar sub rather than duplicating the image bytes.
    const profile = linkTreeProfile(publishTree);
    if (avatarAbsUrl && profile.photo) {
      profile.photo = avatarAbsUrl;
    }
    if (Object.keys(profile).length) {
      pubToSend.profile = profile;
    }
    return pubToSend;
  };

  const publish = async () => {
    if (!kp || !canPublish) {
      return;
    }
    setWorking(true);
    try {
      const privateValue = normalizedPrivateValue();
      await updateData(
        kp,
        path,
        privateValue,
        await buildPubToSend(privateValue),
      );
      setPathIsNew(false);
      flashStatus(
        `Your ${modeSummary(priv.value.type).toLowerCase()} is live.`,
      );
      setJustPublished(true);
      setShareOpen(true);
    } catch (e) {
      showError((e as Error).message);
    } finally {
      setWorking(false);
    }
  };

  // Export the page as a ZIP: priv.cbor plus pub exploded into a directory
  // (index.html and any subresources).
  const exportBackup = async () => {
    setWorking(true);
    try {
      const privateValue = normalizedPrivateValue();
      const blob = await exportBackupZip(
        privateValue,
        await buildPubToSend(privateValue),
      );
      const base = (path.trim() || "page").replace(/[^\w.-]+/g, "-");
      // Filesystem-safe timestamp, e.g. 2026-07-09T153045 (no colons).
      const stamp = new Date().toISOString().slice(0, 19).replace(/:/g, "");
      downloadFile(`found.as-${base}-${stamp}.zip`, blob);
    } catch (e) {
      showError((e as Error).message);
    } finally {
      setWorking(false);
    }
  };

  const importInputRef = useRef<HTMLInputElement>(null);
  const importBackup = async (event: Event) => {
    const input = event.target as HTMLInputElement;
    const chosen = input.files?.[0];
    input.value = "";
    if (!chosen) return;
    setWorking(true);
    try {
      priv.value = await readPrivFromBackup(
        new Uint8Array(await chosen.arrayBuffer()),
      );
      flashStatus("Imported — review and publish to make it live.");
    } catch (e) {
      showError((e as Error).message);
    } finally {
      setWorking(false);
    }
  };

  const applyRemember = () => {
    if (!kp) return;
    if (remember) {
      rememberPage(path.trim(), kp);
    } else {
      forgetPage(path.trim());
    }
    setRemembered(loadRemembered());
  };

  const openRemembered = (p: string) => {
    // Explicitly chosen from the remembered list — open it. Set the key here
    // rather than leaning on the path-change effect, since picking the current
    // path (e.g. "/" from the root entry screen) wouldn't change it and so
    // wouldn't re-run anything.
    const saved = rememberedKeyPair(p.trim());
    autoOpenPath.current = p.trim();
    explicitOpen.current = true;
    setPw("");
    setPath(p);
    if (saved) {
      setKP(saved);
      setRemember(true);
      setSetupComplete(true);
    }
  };

  const forgetRemembered = (p: string) => {
    forgetPage(p);
    setRemembered(loadRemembered());
    if (p === path.trim()) {
      setRemember(false);
    }
  };

  if (!setupComplete || pwStatus !== true) {
    return (
      <main className="app-shell">
        <SetupPanel
          path={path}
          setPath={setPath}
          pw={pw}
          setPw={setPw}
          working={working}
          pwStatus={pwStatus}
          pathIsNew={pathIsNew}
          remember={remember}
          setRemember={setRemember}
          remembered={remembered}
          openRemembered={openRemembered}
          forgetRemembered={forgetRemembered}
          onContinue={() => {
            if (pathIsNew) {
              setType(Type.LINK_TREE);
            }
            applyRemember();
            setSetupComplete(true);
          }}
        />
      </main>
    );
  }

  return (
    <main className={`app-shell ${wideEditor ? "" : "app-shell-compact"}`}>
      <header className="topbar">
        <div className="topbar-id">
          <a
            className="topbar-home"
            href="/"
            aria-label="found.as home — switch to another page"
          >
            found.as
          </a>
          <a
            className="page-url"
            href={shareUrl}
            target="_blank"
            rel="noreferrer"
            title="Open your public page"
          >
            {shareDomain ?? `/${path.trim()}`}
          </a>
        </div>
        <div className="topbar-actions">
          {!pathIsNew && (
            <button
              type="button"
              className="secondary topbar-share"
              onClick={() => {
                setJustPublished(false);
                setShareOpen(true);
              }}
            >
              Share
            </button>
          )}
          <button
            type="button"
            className="secondary topbar-menu-button"
            popovertarget="topbarMenu"
          >
            Menu
          </button>
        </div>
      </header>

      <div popover="auto" id="topbarMenu" className="popover-panel topbar-menu">
        <div className="popover-heading">
          <h2>Menu</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close"
            onClick={closeMenu}
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <p className="menu-heading">Backup</p>
        <button
          type="button"
          className="secondary"
          onClick={() => {
            closeMenu();
            saveRecoveryKit();
          }}
        >
          Save recovery kit
        </button>
        <button
          type="button"
          className="secondary"
          onClick={() => {
            closeMenu();
            exportBackup();
          }}
        >
          Export backup (.zip)
        </button>
        <button
          type="button"
          className="secondary"
          onClick={() => {
            closeMenu();
            importInputRef.current?.click();
          }}
        >
          Import backup
        </button>

        <p className="menu-heading">Address</p>
        {!pathIsNew && (
          <button
            type="button"
            className="secondary"
            onClick={() => {
              closeMenu();
              setRenameTo("");
              document.getElementById("renamePage")?.showPopover();
            }}
          >
            Change address
          </button>
        )}
        <button
          type="button"
          className="secondary"
          onClick={() => {
            closeMenu();
            document.getElementById("customDomain")?.showPopover();
          }}
        >
          Manage domains
        </button>

        <p className="menu-heading">Access</p>
        <button
          type="button"
          className="secondary"
          onClick={() => {
            closeMenu();
            document.getElementById("changePw")?.showPopover();
          }}
        >
          Change password
        </button>
        {!pathIsNew && (
          <button
            type="button"
            className="secondary"
            onClick={() => {
              closeMenu();
              if (remembered.some((r) => r.path === path.trim())) {
                forgetPage(path.trim());
                setRemember(false);
              } else if (kp) {
                rememberPage(path.trim(), kp);
                setRemember(true);
              }
              setRemembered(loadRemembered());
            }}
          >
            {remembered.some((r) => r.path === path.trim())
              ? "Forget on this device"
              : "Remember on this device"}
          </button>
        )}
        {!pathIsNew && (
          <>
            <hr className="menu-divider" />
            <button
              type="button"
              className="secondary menu-danger"
              onClick={() => {
                closeMenu();
                setDeleteConfirm("");
                document.getElementById("deletePage")?.showPopover();
              }}
            >
              Delete page
            </button>
          </>
        )}
      </div>

      <input
        ref={importInputRef}
        type="file"
        accept=".zip,application/zip,application/octet-stream"
        className="sr-only"
        onChange={importBackup}
      />

      <section className="workspace workspace-compact">
        <div className="editor-panel">
          <BuilderModePicker
            mode={builderMode}
            setMode={setBuilderMode}
            advancedType={advancedType}
            setAdvancedType={setType}
          />

          {priv.value.type === Type.LINK_TREE ? (
            <LinkTreeEditor
              priv={priv}
              displayAddress={shareDisplay}
              onError={showError}
            />
          ) : priv.value.type === Type.REDIR ? (
            <RedirectEditor priv={priv} />
          ) : priv.value.type === Type.BYTES ? (
            <FileEditor file={file} setFile={setFile} onError={showError} />
          ) : pub !== null ? (
            <PageEditor priv={priv} pub={pub} />
          ) : null}
        </div>
      </section>

      {validationErrors.length > 0 && (
        <div className="notice error-box" role="alert">
          {validationErrors.map((error) => (
            <p key={error}>{error}</p>
          ))}
        </div>
      )}

      <footer className="publish-bar">
        <div className="publish-status" aria-live="polite">
          {statusMessage ||
            (!working && contactNeedsContent
              ? "Add a name, photo, description, or link."
              : "")}
        </div>
        <div className="publish-actions">
          <button type="button" disabled={!canPublish} onClick={publish}>
            {working ? "Working…" : "Publish"}
          </button>
        </div>
      </footer>

      <div
        popover="auto"
        id="changePw"
        className="popover-panel password-popover"
      >
        <div className="popover-heading">
          <h2>Update password</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close"
            onClick={() => document.getElementById("changePw")?.hidePopover()}
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <label className="field stack">
          <span>New password</span>
          <input
            type="password"
            value={newPw}
            onInput={(e) => setNewPw((e.target as HTMLInputElement).value)}
          />
        </label>
        <p className="help">
          This replaces your page's key, so any recovery kit you've saved stops
          working — save a fresh one afterwards.
        </p>
        <div className="popover-actions">
          <button
            type="button"
            onClick={() => {
              if (!kp) {
                return;
              }
              setWorking(true);
              updatePw(kp, path, newPw)
                .then(() => {
                  setPw(newPw);
                  setNewPw("");
                  flashStatus("Password changed — save a fresh recovery kit.");
                  document.getElementById("changePw")?.hidePopover();
                })
                .catch((e) => {
                  showError(e.message);
                })
                .finally(() => {
                  setWorking(false);
                });
            }}
          >
            Save
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => document.getElementById("changePw")?.hidePopover()}
          >
            Cancel
          </button>
        </div>
      </div>


      <div popover="auto" id="renamePage" className="popover-panel">
        <div className="popover-heading">
          <h2>Change address</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close"
            onClick={() => document.getElementById("renamePage")?.hidePopover()}
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <label className="field stack">
          <span>New address</span>
          <span className="path-field">
            <span className="path-prefix">found.as/</span>
            <input
              type="text"
              aria-label="New page path"
              maxLength={64}
              value={renameTo}
              autoComplete="off"
              autoCapitalize="off"
              spellcheck={false}
              placeholder={path.trim()}
              onInput={(e) =>
                setRenameTo(
                  (e.target as HTMLInputElement).value.replace(/\s+/g, ""),
                )
              }
            />
          </span>
        </label>
        {renameDiscouraged && (
          <p className="help warning-text">
            Lowercase letters, numbers and hyphens make the best address —
            capitals and special characters are harder to type and share.
          </p>
        )}
        <p className="help">
          Your page moves to the new address. The old one stops working, and any
          custom domains follow automatically.
        </p>
        <div className="popover-actions">
          <button
            type="button"
            disabled={
              working || !renameTo.trim() || renameTo.trim() === path.trim()
            }
            onClick={() => {
              if (!kp) {
                return;
              }
              const target = renameTo.trim();
              setWorking(true);
              renamePage(kp, path, target, pw)
                .then(() => {
                  document.getElementById("renamePage")?.hidePopover();
                  setPathIsNew(false);
                  renamingRef.current = true;
                  setPath(target);
                  flashStatus(`Now at found.as/${target}.`);
                })
                .catch((e) => showError(e.message))
                .finally(() => setWorking(false));
            }}
          >
            Move page
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => document.getElementById("renamePage")?.hidePopover()}
          >
            Cancel
          </button>
        </div>
      </div>

      <div popover="auto" id="deletePage" className="popover-panel">
        <div className="popover-heading">
          <h2>Delete page</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close"
            onClick={() => document.getElementById("deletePage")?.hidePopover()}
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <p className="help warning-text">
          This permanently removes found.as/{path.trim()} and releases any
          custom domains. There's no undo.
        </p>
        <label className="field stack">
          <span>
            Type <strong>{path.trim()}</strong> to confirm
          </span>
          <input
            type="text"
            autoComplete="off"
            autoCapitalize="off"
            spellcheck={false}
            value={deleteConfirm}
            onInput={(e) =>
              setDeleteConfirm((e.target as HTMLInputElement).value)
            }
          />
        </label>
        <div className="popover-actions">
          <button
            type="button"
            disabled={working || deleteConfirm.trim() !== path.trim()}
            onClick={() => {
              if (!kp) {
                return;
              }
              setWorking(true);
              deletePage(kp, path)
                .then(() => {
                  // A deleted page can never be reopened, so drop it from this
                  // device's remembered pages.
                  forgetPage(path.trim());
                  window.location.href = "/";
                })
                .catch((e) => {
                  showError(e.message);
                  setWorking(false);
                });
            }}
          >
            Delete permanently
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => document.getElementById("deletePage")?.hidePopover()}
          >
            Cancel
          </button>
        </div>
      </div>

      {kp && (
        <DomainPopover
          kp={kp}
          path={path.trim()}
          shareDomain={shareDomain}
          setShareDomain={chooseMainAddress}
          onError={showError}
        />
      )}

      {signatureAvailable && !shareOpen && (
        <EmailSignaturePopover tree={tree} url={shareUrl} onError={showError} />
      )}

      {shareOpen && (
        <div
          className="publish-success-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="publish-success-title"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShareOpen(false);
          }}
        >
          <div className="publish-success">
            <div className="popover-heading">
              <h2 id="publish-success-title">
                {justPublished ? "You're live 🎉" : "Share"}
              </h2>
              <button
                type="button"
                className="icon-button"
                aria-label="Close"
                onClick={() => setShareOpen(false)}
              >
                <span aria-hidden="true">×</span>
              </button>
            </div>
            <button
              type="button"
              className="qr-frame"
              onClick={saveQr}
              title="Save QR code"
            >
              <QrCode value={vcardQrShown ? qrVcard! : shareUrl} />
            </button>
            {qrVcard && (
              <div className="qr-mode" role="group" aria-label="QR code type">
                <button
                  type="button"
                  className="secondary"
                  aria-pressed={!vcardQrShown}
                  onClick={() => setQrMode("link")}
                >
                  Page link
                </button>
                <button
                  type="button"
                  className="secondary"
                  aria-pressed={vcardQrShown}
                  onClick={() => setQrMode("vcard")}
                >
                  Contact card
                </button>
              </div>
            )}
            {vcardQrShown ? (
              <p className="help qr-mode-help">Works offline</p>
            ) : (
              <a
                className="success-url"
                href={shareUrl}
                target="_blank"
                rel="noreferrer"
              >
                {shareUrl}
              </a>
            )}
            <div className="success-actions">
              <button type="button" onClick={sharePublicUrl} aria-live="polite">
                {canShare ? "Share" : copied ? "Copied ✓" : "Copy link"}
              </button>
              <button type="button" className="secondary" onClick={saveQr}>
                Save QR
              </button>
              {signatureAvailable && (
                <button
                  type="button"
                  className="secondary"
                  popovertarget="emailSignature"
                >
                  Email signature
                </button>
              )}
              {priv.value.type === Type.LINK_TREE && (
                <button
                  type="button"
                  className="secondary"
                  onClick={openPrintables}
                >
                  Cards &amp; poster
                </button>
              )}
              <a
                className="button-link secondary"
                href={shareUrl}
                target="_blank"
                rel="noreferrer"
              >
                Open
              </a>
            </div>
            {signatureAvailable && (
              <EmailSignaturePopover
                tree={tree}
                url={shareUrl}
                onError={showError}
              />
            )}
          </div>
        </div>
      )}

      {toast && (
        <div className="toast" role="alert" onClick={() => setToast("")}>
          {toast}
        </div>
      )}
    </main>
  );
}
