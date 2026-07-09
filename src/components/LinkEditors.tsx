import { accentPair, legacyAccents, themeAccentDefaults } from "../color";
import {
  blobToDataUrl,
  canImportLinkIcon,
  compressAvatar,
  compressBg,
  compressCover,
  compressOgImage,
  importLinkIcon,
} from "../image";
import {
  activeValidLinks,
  canFeature,
  defaultLinkItem,
  ensureLinkTree,
  isDefaultLinkValue,
  isSection,
  isText,
  isVideo,
  normalizeLink,
  normalizeUrl,
  renderTextBlockMarkdown,
  sanitizeEditorHtml,
  youTubeEmbedHtml,
  youTubeId,
} from "../linktree";
import { renderOgImage } from "../og";
import { linkTreeToHtml } from "../render";
import {
  avatarImageSrc,
  avatarRadius,
  clampBtnAlpha,
  clampBtnBlur,
  clampCoverHeight,
  clampLighten,
  clampShade,
  clampZoom,
  cornerRadius,
  fontStack,
  linkIconEmoji,
  linkIconSrc,
  pageBackground,
  sanitizeObjectPosition,
} from "../theme";
import {
  AvatarShape,
  Background,
  ButtonStyle,
  Corners,
  CoverFit,
  FontChoice,
  LinkItem,
  LinkKind,
  LinkTree,
  Private,
  Public,
  SocialPreview,
  Type,
  addGroups,
  handleKinds,
  identityKinds,
  kindDefaultIcons,
  kindExamples,
  kindIconSites,
  kindLabels,
} from "../types";
import { previewBootstrap, splitGraphemes } from "../util";
import { vcardEligible } from "../vcard";
import { AccentWheel } from "./AccentWheel";
import { Signal } from "@preact/signals";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";

export function PageEditor({
  priv,
  pub,
}: {
  priv: Signal<Private>;
  pub: Public;
}) {
  const ifref = useRef<HTMLIFrameElement>(null);
  const [iframeReady, setIframeReady] = useState(false);

  useEffect(() => {
    if (iframeReady) {
      ifref.current?.contentWindow?.postMessage(
        { type: "preview-update", html: pub.html },
        "*",
      );
    }
  }, [pub.html, iframeReady]);

  return (
    <div className="edit-and-preview">
      <label className="field stack">
        <span className="sr-only">
          {priv.value.type === Type.HTML_PAGE
            ? "HTML content"
            : "Markdown content"}
        </span>
        <textarea
          placeholder={
            priv.value.type === Type.HTML_PAGE
              ? "Start writing HTML"
              : "Start writing GitHub-flavored markdown.\n\nOptional front matter:\n---\ntitle: Page title\n---"
          }
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
      </label>
      <iframe
        className="preview"
        title="Page preview"
        ref={ifref}
        onLoad={() => setIframeReady(true)}
        srcdoc={previewBootstrap}
      ></iframe>
    </div>
  );
}

export function RedirectEditor({ priv }: { priv: Signal<Private> }) {
  const normalizedUrl = useMemo(
    () => normalizeUrl(priv.value.redir),
    [priv.value.redir],
  );

  const valid = useMemo(() => URL.canParse(normalizedUrl), [normalizedUrl]);

  return (
    <section className="panel-section">
      <label className="field stack">
        <span>Redirect destination</span>
        <input
          type="url"
          value={priv.value.redir}
          placeholder="example.com"
          aria-describedby="redirect-help"
          onInput={(e) => {
            priv.value = {
              ...priv.value,
              redir: (e.target as HTMLInputElement).value,
            };
          }}
        />
      </label>
      <p id="redirect-help" className={valid ? "help" : "help error-text"}>
        {valid ? normalizedUrl : "Enter a valid web address."}
      </p>
    </section>
  );
}

export function FileEditor({
  file,
  setFile,
  onError,
}: {
  file: File | undefined;
  setFile: (file: File | undefined) => void;
  onError: (message: string) => void;
}) {
  return (
    <section className="panel-section">
      <label className="field stack">
        <span>File to publish</span>
        <input
          type="file"
          aria-describedby="file-help"
          onChange={(e) => {
            const target = e.target as HTMLInputElement;
            const selected = target.files?.[0];
            if (!selected) {
              setFile(undefined);
              return;
            }
            if (selected.size > 5 * 1024 * 1024) {
              onError("That file is over 5MB. Choose a smaller file.");
              target.value = target.defaultValue;
              setFile(undefined);
              return;
            }
            setFile(selected);
          }}
        />
      </label>
      <p id="file-help" className="help">
        {file
          ? `${file.name} is ready to publish.`
          : "Choose a file under 5MB."}
      </p>
    </section>
  );
}

export function linkValueLabel(kind: LinkKind): string {
  if (kind === "phone" || kind === "whatsapp") return "Number";
  if (kind === "email") return "Email address";
  if (kind === "address") return "Address or map link";
  if (kind === "googlereview") return "Google review link";
  if (kind === "discord") return "Invite link";
  if (kind === "cashapp") return "Cashtag or link";
  if (kind === "substack") return "Publication or link";
  if (kind === "mastodon" || kind === "matrix" || kind === "bluesky") {
    return "Handle or link";
  }
  if (handleKinds.includes(kind)) return "Username or link";
  return "Link";
}

export function EditableLink({
  link,
  index,
  total,
  updateLink,
  setFeatured,
  setIcon,
  onError,
  removeLink,
  moveTo,
  moveBy,
  dragging,
  setDragging,
  dropTarget,
  dropAfter,
  setDragOver,
  selected,
  setSelected,
}: {
  link: LinkItem;
  index: number;
  total: number;
  updateLink: (link: LinkItem) => void;
  setFeatured: (id: string, featured: boolean) => void;
  setIcon: (id: string, icon: string | undefined) => void;
  onError: (message: string) => void;
  removeLink: () => void;
  moveTo: (draggedId: string, targetId: string, after: boolean) => void;
  moveBy: (id: string, delta: number) => void;
  dragging: boolean;
  setDragging: (id: string) => void;
  dropTarget: boolean;
  dropAfter: boolean;
  setDragOver: (id: string, after?: boolean) => void;
  selected: boolean;
  setSelected: (id: string) => void;
}) {
  const normalized = normalizeLink(link);
  const sectionItem = isSection(link);
  const textItem = isText(link);
  const videoItem = isVideo(link);
  const blockItem = sectionItem || textItem || videoItem;
  // A markdown text block previews its rendered content (matching the published
  // page) instead of showing raw source; needs a non-button element since it
  // may contain block content.
  const mdPreview =
    textItem && Boolean(link.markdown) && link.label.trim() !== "";
  const videoId = videoItem ? youTubeId(link.value.trim()) : null;
  const fieldId = `link-${link.id}`;
  const detailId = `${fieldId}-detail`;
  const valueLabel = linkValueLabel(link.kind);
  const label = link.label.trim() || kindLabels[link.kind];
  const optionalIncomplete = Boolean(
    normalized.error && isDefaultLinkValue(link),
  );
  const featurable = Boolean(normalized.href && !normalized.error);
  const featuredShown = Boolean(link.featured && featurable);
  const iconSrc = linkIconSrc(link.icon);
  const iconEmoji = linkIconEmoji(link.icon);
  const iconImportUrl = canImportLinkIcon(normalized.href)
    ? normalized.href
    : kindIconSites[link.kind];
  const iconImportable = !blockItem && Boolean(iconImportUrl);
  const [importingIcon, setImportingIcon] = useState(false);
  const [iconStatus, setIconStatus] = useState("");

  const importIcon = () => {
    if (!iconImportUrl) return;
    setImportingIcon(true);
    setIconStatus("");
    importLinkIcon(iconImportUrl)
      .then((icon) => {
        setIcon(link.id, icon);
        setIconStatus("Icon saved into your page.");
      })
      .catch((error) => {
        onError((error as Error).message);
      })
      .finally(() => setImportingIcon(false));
  };

  return (
    <article
      className={`editable-link ${selected ? "is-selected" : ""} ${dragging ? "is-dragging" : ""} ${dropTarget ? "is-drop-target" : ""} ${dropTarget && dropAfter ? "is-drop-after" : ""} ${link.enabled ? "" : "is-disabled"} ${sectionItem ? "is-section" : ""} ${textItem ? "is-text" : ""} ${featuredShown ? "is-featured" : ""}`}
      draggable
      onDragStart={(event) => {
        if (!event.dataTransfer) return;
        event.dataTransfer.effectAllowed = "move";
        event.dataTransfer.setData("text/plain", link.id);
        setDragging(link.id);
      }}
      onDragOver={(event) => {
        event.preventDefault();
        if (event.dataTransfer) {
          event.dataTransfer.dropEffect = "move";
        }
        if (!dragging) {
          const rect = event.currentTarget.getBoundingClientRect();
          setDragOver(link.id, event.clientY > rect.top + rect.height / 2);
        }
      }}
      onDrop={(event) => {
        event.preventDefault();
        const draggedId = event.dataTransfer?.getData("text/plain") ?? "";
        const rect = event.currentTarget.getBoundingClientRect();
        moveTo(draggedId, link.id, event.clientY > rect.top + rect.height / 2);
        setDragging("");
        setDragOver("");
      }}
      onDragEnd={() => {
        setDragging("");
        setDragOver("");
      }}
    >
      <div className="editable-link-row">
        <span className="reorder" title="Drag to reorder">
          <span className="drag-grip" aria-hidden="true"></span>
          <button
            type="button"
            className="reorder-button"
            aria-label={`Move ${label} up`}
            disabled={index === 0}
            onClick={() => moveBy(link.id, -1)}
          >
            <span aria-hidden="true">▲</span>
          </button>
          <button
            type="button"
            className="reorder-button"
            aria-label={`Move ${label} down`}
            disabled={index === total - 1}
            onClick={() => moveBy(link.id, 1)}
          >
            <span aria-hidden="true">▼</span>
          </button>
        </span>
        {mdPreview ? (
          <div
            className="md-preview"
            role="button"
            tabIndex={0}
            aria-expanded={selected}
            aria-controls={selected ? detailId : undefined}
            onClick={() => setSelected(selected ? "" : link.id)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                setSelected(selected ? "" : link.id);
              }
            }}
            dangerouslySetInnerHTML={{
              __html: sanitizeEditorHtml(renderTextBlockMarkdown(link.label)),
            }}
          />
        ) : videoItem ? (
          <div
            className="video-preview"
            role="button"
            tabIndex={0}
            aria-expanded={selected}
            aria-controls={selected ? detailId : undefined}
            onClick={() => setSelected(selected ? "" : link.id)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                setSelected(selected ? "" : link.id);
              }
            }}
          >
            {videoId ? (
              // Controlled embed HTML (fixed nocookie iframe) — safe to inject.
              <div
                dangerouslySetInnerHTML={{ __html: youTubeEmbedHtml(videoId) }}
              />
            ) : (
              <span className="video-placeholder">▶ Add a YouTube video</span>
            )}
          </div>
        ) : (
          <button
            type="button"
            className="contact-button-preview"
            aria-expanded={selected}
            aria-controls={selected ? detailId : undefined}
            onClick={() => setSelected(selected ? "" : link.id)}
          >
            {iconSrc ? (
              <img className="row-link-icon" src={iconSrc} alt="" />
            ) : iconEmoji ? (
              <span className="row-link-emoji" aria-hidden="true">
                {iconEmoji}
              </span>
            ) : null}
            {featuredShown && (
              <span className="featured-tag">
                <span aria-hidden="true">★ </span>Featured
              </span>
            )}
            {label}
            {link.badge?.trim() && (
              <span className="row-badge">{link.badge.trim()}</span>
            )}
            {link.desc?.trim() && (
              <span className="row-desc">{link.desc.trim()}</span>
            )}
          </button>
        )}
        <button
          type="button"
          className="icon-button"
          aria-label={`Remove ${label}`}
          title="Remove"
          onClick={removeLink}
        >
          <span aria-hidden="true">×</span>
        </button>
      </div>

      {selected && (
        <div className="link-edit-panel" id={detailId}>
          <label className="field stack">
            <span>
              {videoItem
                ? "YouTube link"
                : sectionItem
                  ? "Heading"
                  : textItem
                    ? "Text"
                    : "Button text"}
            </span>
            {videoItem ? (
              <input
                type="url"
                value={link.value}
                placeholder={kindExamples.video}
                aria-describedby={`${detailId}-status`}
                onInput={(e) =>
                  updateLink({
                    ...link,
                    value: (e.target as HTMLInputElement).value,
                  })
                }
              />
            ) : textItem ? (
              <textarea
                rows={3}
                value={link.label}
                placeholder={kindExamples.text}
                onInput={(e) =>
                  updateLink({
                    ...link,
                    label: (e.target as HTMLTextAreaElement).value,
                  })
                }
              ></textarea>
            ) : (
              <input
                type="text"
                value={link.label}
                placeholder={
                  sectionItem ? kindExamples.section : kindLabels[link.kind]
                }
                aria-describedby={
                  sectionItem ? `${detailId}-status` : undefined
                }
                onInput={(e) =>
                  updateLink({
                    ...link,
                    label: (e.target as HTMLInputElement).value,
                  })
                }
              />
            )}
          </label>
          {textItem && (
            <div className="panel-group">
              <label className="show-toggle">
                <input
                  type="checkbox"
                  checked={Boolean(link.markdown)}
                  aria-describedby={`${detailId}-md`}
                  onChange={(e) =>
                    updateLink({
                      ...link,
                      markdown:
                        (e.target as HTMLInputElement).checked || undefined,
                    })
                  }
                />
                <span>Format the text</span>
              </label>
              <p id={`${detailId}-md`} className="help">
                Markdown: <strong>**bold**</strong>, <em>*italic*</em>, links,
                lists and headings.
              </p>
            </div>
          )}
          {!blockItem && (
            <div className="panel-group">
              <label className="field stack">
                <span>{valueLabel}</span>
                <input
                  id={fieldId}
                  type={link.kind === "email" ? "email" : "text"}
                  value={link.value}
                  placeholder={kindExamples[link.kind]}
                  aria-describedby={`${detailId}-status`}
                  onInput={(e) =>
                    updateLink({
                      ...link,
                      value: (e.target as HTMLInputElement).value,
                    })
                  }
                />
              </label>
              {link.kind === "email" && (
                <p className="help">
                  Need a public email address? Create a forwarding alias at{" "}
                  <a href="https://cc.me/hi" target="_blank" rel="noreferrer">
                    cc.me/hi
                  </a>
                  .
                </p>
              )}
              {link.kind === "googlereview" && (
                <p className="help">
                  In your Google Business Profile, use “Ask for reviews” to copy
                  your review link — it looks like{" "}
                  <code>g.page/r/…/review</code>.
                </p>
              )}
            </div>
          )}
          {!blockItem && (
            <div className="panel-group">
              <label className="field stack">
                <span>Subtitle</span>
                <input
                  type="text"
                  value={link.desc ?? ""}
                  maxLength={80}
                  placeholder="Optional line under the button"
                  onInput={(e) =>
                    updateLink({
                      ...link,
                      desc: (e.target as HTMLInputElement).value || undefined,
                    })
                  }
                />
              </label>
              <label className="field stack">
                <span>Badge</span>
                <input
                  type="text"
                  value={link.badge ?? ""}
                  maxLength={16}
                  placeholder="e.g. New"
                  onInput={(e) =>
                    updateLink({
                      ...link,
                      badge: (e.target as HTMLInputElement).value || undefined,
                    })
                  }
                />
              </label>
            </div>
          )}
          <label className="show-toggle">
            <input
              type="checkbox"
              checked={link.enabled}
              onChange={(e) =>
                updateLink({
                  ...link,
                  enabled: (e.target as HTMLInputElement).checked,
                })
              }
            />
            <span>Show on page</span>
          </label>
          {!blockItem && (
            <label className="show-toggle">
              <input
                type="checkbox"
                checked={Boolean(link.card)}
                onChange={(e) =>
                  updateLink({
                    ...link,
                    card: (e.target as HTMLInputElement).checked || undefined,
                  })
                }
              />
              <span>Include on business cards</span>
            </label>
          )}
          {canFeature(link) && (
            <label className="show-toggle">
              <input
                type="checkbox"
                checked={Boolean(link.featured)}
                disabled={!link.featured && !featurable}
                onChange={(e) =>
                  setFeatured(link.id, (e.target as HTMLInputElement).checked)
                }
              />
              <span>Feature this link</span>
            </label>
          )}
          {identityKinds.has(link.kind) && (
            <div className="panel-group">
              <label className="show-toggle">
                <input
                  type="checkbox"
                  checked={link.relMe !== false}
                  aria-describedby={`${detailId}-relme`}
                  onChange={(e) =>
                    updateLink({
                      ...link,
                      relMe: (e.target as HTMLInputElement).checked,
                    })
                  }
                />
                <span>This is really me</span>
              </label>
              <p id={`${detailId}-relme`} className="help">
                Publishes this link with rel="me", which tells other sites it's
                yours — Mastodon uses it for its green "verified" check. Untick
                it if this link isn't your own.
              </p>
            </div>
          )}
          {!blockItem && (
            <div className="link-icon-block">
              <div className="link-icon-actions">
                {(iconSrc || iconEmoji) && (
                  <span className="link-icon-preview" aria-hidden="true">
                    {iconSrc ? <img src={iconSrc} alt="" /> : iconEmoji}
                  </span>
                )}
                <input
                  type="text"
                  className="emoji-input"
                  aria-label="Emoji icon"
                  value={iconEmoji ?? ""}
                  placeholder={kindDefaultIcons[link.kind] ?? "😀"}
                  onInput={(e) => {
                    const graphemes = splitGraphemes(
                      (e.target as HTMLInputElement).value.trim(),
                    );
                    const fresh = iconEmoji
                      ? graphemes.filter((g) => g !== iconEmoji)
                      : graphemes;
                    const picked = fresh.length ? fresh : graphemes;
                    setIcon(
                      link.id,
                      picked.length ? picked[picked.length - 1] : undefined,
                    );
                    setIconStatus("");
                  }}
                />
                {iconImportable && (
                  <button
                    type="button"
                    className="secondary"
                    disabled={importingIcon}
                    onClick={importIcon}
                  >
                    {importingIcon
                      ? "Importing…"
                      : iconSrc
                        ? "Refresh icon"
                        : "Import icon"}
                  </button>
                )}
                {(iconSrc || iconEmoji) && (
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => {
                      setIcon(link.id, undefined);
                      setIconStatus("");
                    }}
                  >
                    Remove icon
                  </button>
                )}
              </div>
              <p className="help">
                {iconStatus ||
                  (iconImportable
                    ? "Show an icon on this button — type an emoji, or import the site's icon. It's fetched once and saved into your page."
                    : "Show an icon on this button — type any emoji.")}
              </p>
            </div>
          )}
          {sectionItem ? (
            <p id={`${detailId}-status`} className="link-status">
              {!link.label.trim()
                ? "Hidden until it has text."
                : link.enabled
                  ? "Shown as a heading."
                  : "Hidden."}
            </p>
          ) : textItem ? (
            <p id={`${detailId}-status`} className="link-status">
              {!link.label.trim()
                ? "Hidden until it has text."
                : link.enabled
                  ? "Shown as text."
                  : "Hidden."}
            </p>
          ) : videoItem ? (
            <p
              id={`${detailId}-status`}
              className={`link-status ${normalized.error ? "error-text" : ""}`}
            >
              {normalized.error ??
                (!link.value.trim()
                  ? "Add a YouTube link."
                  : link.enabled
                    ? "Shown as a video."
                    : "Hidden.")}
            </p>
          ) : (
            <p
              id={`${detailId}-status`}
              className={`link-status ${
                normalized.error && !optionalIncomplete
                  ? "error-text"
                  : normalized.warning
                    ? "warning-text"
                    : ""
              }`}
            >
              {(optionalIncomplete ? undefined : normalized.error) ??
                normalized.warning ??
                (normalized.href
                  ? normalized.href
                  : link.featured
                    ? "Featured — hidden until complete."
                    : "Hidden until complete.")}
            </p>
          )}
        </div>
      )}
      <span className="sr-only">
        {index + 1} of {total}
      </span>
    </article>
  );
}

// A framed image you drag to pan and scroll (or slide) to zoom — the visible
// region maps 1:1 to the published crop (object-position + scale + origin).
export function RegionEditor({
  src,
  pos,
  zoom,
  onChange,
  className,
  style,
}: {
  src: string;
  pos: string;
  zoom: number;
  onChange: (pos: string, zoom: number) => void;
  className?: string;
  style?: Record<string, string | number>;
}) {
  const frameRef = useRef<HTMLDivElement>(null);
  const drag = useRef<{
    sx: number;
    sy: number;
    x: number;
    y: number;
    w: number;
    h: number;
  } | null>(null);
  const clampPct = (v: number) => Math.min(100, Math.max(0, v));

  return (
    <div
      ref={frameRef}
      className={`region-frame ${className ?? ""}`}
      style={style}
      onPointerDown={(e) => {
        const el = frameRef.current;
        if (!el) return;
        const [x, y] = pos.replace(/%/g, "").split(/\s+/).map(Number);
        drag.current = {
          sx: e.clientX,
          sy: e.clientY,
          x,
          y,
          w: el.clientWidth,
          h: el.clientHeight,
        };
        el.setPointerCapture(e.pointerId);
      }}
      onPointerMove={(e) => {
        const d = drag.current;
        if (!d) return;
        const nx = clampPct(d.x - ((e.clientX - d.sx) / d.w / zoom) * 100);
        const ny = clampPct(d.y - ((e.clientY - d.sy) / d.h / zoom) * 100);
        onChange(`${Math.round(nx)}% ${Math.round(ny)}%`, zoom);
      }}
      onPointerUp={() => {
        drag.current = null;
      }}
      onWheel={(e) => {
        e.preventDefault();
        onChange(
          pos,
          clampZoom(Math.round((zoom - e.deltaY * 0.0025) * 100) / 100),
        );
      }}
    >
      <img
        src={src}
        alt=""
        draggable={false}
        style={{
          objectFit: "cover",
          objectPosition: pos,
          transform: `scale(${zoom})`,
          transformOrigin: pos,
        }}
      />
      <input
        className="region-zoom"
        type="range"
        min={1}
        max={4}
        step={0.05}
        value={zoom}
        aria-label="Zoom"
        onPointerDown={(e) => e.stopPropagation()}
        onInput={(e) =>
          onChange(pos, clampZoom(Number((e.target as HTMLInputElement).value)))
        }
      />
    </div>
  );
}

export function CoverEditor({
  tree,
  updateTree,
  onError,
}: {
  tree: LinkTree;
  updateTree: (tree: LinkTree) => void;
  onError: (message: string) => void;
}) {
  const src = avatarImageSrc(tree.coverUrl);
  const [status, setStatus] = useState("");
  const fit = tree.coverFit === "contain" ? "contain" : "cover";
  const pos = sanitizeObjectPosition(tree.coverPos);

  const upload = (file?: File) => {
    if (!file) return;
    setStatus("Preparing…");
    compressCover(file)
      .then((img) => {
        updateTree({ ...tree, coverUrl: img.dataUrl });
        setStatus("");
      })
      .catch((e) => {
        setStatus("");
        onError((e as Error).message);
      });
  };
  const pickFile = (e: Event) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    upload(file);
  };

  if (!src) {
    return (
      <label className="cover-add">
        <span>+ Add cover photo</span>
        <input
          type="file"
          accept="image/*"
          className="sr-only"
          onChange={pickFile}
        />
      </label>
    );
  }

  return (
    <div className="cover-editor">
      {fit === "cover" ? (
        <RegionEditor
          src={src}
          pos={pos}
          zoom={clampZoom(tree.coverZoom)}
          onChange={(coverPos, coverZoom) =>
            updateTree({ ...tree, coverPos, coverZoom })
          }
          className="is-fill"
          style={{
            borderRadius: cornerRadius(tree),
            aspectRatio: `440 / ${clampCoverHeight(tree.coverHeight)}`,
          }}
        />
      ) : (
        <div
          className="cover-frame is-fit"
          style={{ borderRadius: cornerRadius(tree) }}
        >
          <img src={src} alt="" />
        </div>
      )}
      <div className="cover-editor-actions">
        <label className="button-link secondary">
          Replace
          <input
            type="file"
            accept="image/*"
            className="sr-only"
            onChange={pickFile}
          />
        </label>
        <button
          type="button"
          className="secondary"
          onClick={() => updateTree({ ...tree, coverUrl: "" })}
        >
          Remove
        </button>
        <label className="cover-fit-field">
          <span>Cover</span>
          <select
            value={fit}
            onChange={(e) =>
              updateTree({
                ...tree,
                coverFit: (e.target as HTMLSelectElement).value as CoverFit,
              })
            }
          >
            <option value="cover">Fill</option>
            <option value="contain">Fit whole image</option>
          </select>
        </label>
      </div>
      {fit === "cover" && (
        <label className="cover-height-field">
          <span>Height</span>
          <input
            type="range"
            min={72}
            max={400}
            step={4}
            value={clampCoverHeight(tree.coverHeight)}
            onInput={(e) =>
              updateTree({
                ...tree,
                coverHeight: Number((e.target as HTMLInputElement).value),
              })
            }
          />
        </label>
      )}
      <label className="show-toggle">
        <input
          type="checkbox"
          checked={Boolean(tree.coverTitle)}
          onChange={(e) =>
            updateTree({
              ...tree,
              coverTitle: (e.target as HTMLInputElement).checked,
            })
          }
        />
        <span>Use the cover as the page's name</span>
      </label>
      {status && <p className="help">{status}</p>}
    </div>
  );
}

export function AvatarEditor({
  tree,
  updateTree,
  onError,
}: {
  tree: LinkTree;
  updateTree: (tree: LinkTree) => void;
  onError: (message: string) => void;
}) {
  const src = avatarImageSrc(tree.avatarUrl);
  const [status, setStatus] = useState("");
  const pos = sanitizeObjectPosition(tree.avatarPos);
  const upload = (file?: File) => {
    if (!file) return;
    setStatus("Preparing…");
    compressAvatar(file)
      .then((img) => {
        updateTree({ ...tree, avatarUrl: img.dataUrl });
        setStatus("");
      })
      .catch((e) => {
        setStatus("");
        onError((e as Error).message);
      });
  };
  const pickFile = (e: Event) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    upload(file);
  };

  if (!src) {
    return (
      <label className="button-link secondary avatar-add">
        Add photo
        <input
          type="file"
          accept="image/*"
          className="sr-only"
          onChange={pickFile}
        />
      </label>
    );
  }

  return (
    <div className="avatar-editor">
      <RegionEditor
        src={src}
        pos={pos}
        zoom={clampZoom(tree.avatarZoom)}
        onChange={(avatarPos, avatarZoom) =>
          updateTree({ ...tree, avatarPos, avatarZoom })
        }
        className="is-avatar"
        style={{ borderRadius: avatarRadius(tree) }}
      />
      <div className="avatar-editor-actions">
        <label className="button-link secondary">
          Replace
          <input
            type="file"
            accept="image/*"
            className="sr-only"
            onChange={pickFile}
          />
        </label>
        <button
          type="button"
          className="secondary"
          onClick={() => updateTree({ ...tree, avatarUrl: "" })}
        >
          Remove
        </button>
      </div>
      {status && <p className="help">{status}</p>}
    </div>
  );
}

// The editor's live preview can be widened or narrowed to taste; the choice is
// remembered across sessions. min(100%, …) keeps it inside the column, so a
// width saved on a wide screen still fits on a phone.
export const PREVIEW_WIDTH_KEY = "foundas.previewWidth";
export const PREVIEW_MIN_WIDTH = 300;
export const PREVIEW_DEFAULT_WIDTH = 496;
export const PREVIEW_WIDTH_STEP = 24;

export function readPreviewWidth(): number {
  try {
    const stored = Number(localStorage.getItem(PREVIEW_WIDTH_KEY));
    if (Number.isFinite(stored) && stored >= PREVIEW_MIN_WIDTH) return stored;
  } catch {
    // Private mode / disabled storage: fall back to the default.
  }
  return PREVIEW_DEFAULT_WIDTH;
}

// The widest the preview can grow: its column, so it never forces a scrollbar.
export function previewMaxWidth(shell: HTMLElement): number {
  return (
    shell.parentElement?.clientWidth ?? shell.getBoundingClientRect().width
  );
}

// A grip on the preview's right edge. Pointer events cover mouse, touch and pen
// alike, so the same drag works on desktop and mobile; arrow keys nudge it too.
//
// Width maps *absolutely* to the cursor, not to relative movement: the preview
// is centered on a fixed point, so its width is twice the cursor's distance from
// that center, clamped to [min, column]. Absolute mapping keeps the grip pinned
// under the cursor — drag past the max and the grip parks at the edge; drag back
// and it re-attaches the instant the cursor returns, with no banked overshoot.
//
// Pointer capture routes the whole gesture (including a release off the grip or
// outside the window) to the handle, so the drag always ends with a commit — a
// missed release would otherwise leave the width uncommitted and the next render
// would snap it back. `buttons === 0` catches a release we somehow still missed.
export function PreviewResizeHandle({
  width,
  commit,
}: {
  width: number;
  commit: (width: number) => void;
}) {
  const onPointerDown = (e: PointerEvent) => {
    e.preventDefault();
    const handle = e.currentTarget as HTMLElement;
    const shell = handle.parentElement as HTMLElement;
    const parent = shell.parentElement;
    const rect = (parent ?? shell).getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const maxWidth = previewMaxWidth(shell);
    let current = shell.getBoundingClientRect().width;
    let done = false;
    const onMove = (ev: PointerEvent) => {
      if (ev.buttons === 0) {
        finish();
        return;
      }
      current = Math.max(
        PREVIEW_MIN_WIDTH,
        Math.min(2 * (ev.clientX - centerX), maxWidth),
      );
      shell.style.setProperty("--pv-w", `${Math.round(current)}px`);
    };
    const finish = () => {
      if (done) return;
      done = true;
      handle.removeEventListener("pointermove", onMove);
      handle.removeEventListener("pointerup", finish);
      handle.removeEventListener("pointercancel", finish);
      handle.removeEventListener("lostpointercapture", finish);
      // No inline width to clear: the drag wrote --pv-w, and the commit below
      // re-renders the same variable, so the final size just stays put.
      commit(current);
    };
    try {
      handle.setPointerCapture(e.pointerId);
    } catch {
      // No capture available; the listeners below still finish the drag.
    }
    handle.addEventListener("pointermove", onMove);
    handle.addEventListener("pointerup", finish);
    handle.addEventListener("pointercancel", finish);
    handle.addEventListener("lostpointercapture", finish);
  };
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    const shell = (e.currentTarget as HTMLElement).parentElement;
    const maxWidth = shell ? previewMaxWidth(shell) : Infinity;
    const step =
      e.key === "ArrowRight" ? PREVIEW_WIDTH_STEP : -PREVIEW_WIDTH_STEP;
    commit(Math.min(width + step, maxWidth));
  };
  return (
    <div
      className="preview-resize-handle"
      role="separator"
      aria-orientation="vertical"
      aria-label="Drag to resize the preview"
      tabIndex={0}
      onPointerDown={onPointerDown}
      onKeyDown={onKeyDown}
    >
      <span className="preview-resize-grip" aria-hidden="true" />
    </div>
  );
}

export function LinkTreeEditor({
  priv,
  displayAddress,
  onError,
}: {
  priv: Signal<Private>;
  displayAddress: string;
  onError: (message: string) => void;
}) {
  const tree = ensureLinkTree(priv.value.linkTree);
  const [draggingId, setDraggingId] = useState("");
  const [dragOverId, setDragOverId] = useState("");
  const [dragAfter, setDragAfter] = useState(false);
  const setDragOver = (id: string, after = false) => {
    setDragOverId(id);
    setDragAfter(after);
  };
  const [selectedLinkId, setSelectedLinkId] = useState("");
  const [ogPreview, setOgPreview] = useState("");
  // What the Auto theme previews as; starts from the device setting, then the
  // Preview toggle takes over. Editor-only — visitors follow their own device.
  const [previewDark, setPreviewDark] = useState(
    () => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false,
  );
  // Which design section is open under the preview. Tabs rather than an
  // accordion: exactly one open at a time, starting on the editor itself.
  const [designTab, setDesignTab] = useState<
    "editor" | "colors" | "style" | "background" | "social"
  >("editor");
  // Remembered preview width; shared by the editable page and the rendered
  // iframe so both keep the size the owner picked.
  const [previewWidth, setPreviewWidth] = useState(readPreviewWidth);
  const commitPreviewWidth = (width: number) => {
    const clamped = Math.round(Math.max(PREVIEW_MIN_WIDTH, width));
    setPreviewWidth(clamped);
    try {
      localStorage.setItem(PREVIEW_WIDTH_KEY, String(clamped));
    } catch {
      // Nothing persisted, but the session still resizes.
    }
  };
  const previewShellStyle = { "--pv-w": `${previewWidth}px` };
  // Tabs that show the rendered page under their controls. The editor tab is
  // the page; Sharing has its own preview image.
  const showsPreview =
    designTab === "colors" ||
    designTab === "style" ||
    designTab === "background";

  // The name and bio grow and shrink with their content, wrapping like the
  // published heading and paragraph do.
  const nameRef = useRef<HTMLTextAreaElement>(null);
  const bioRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    for (const el of [nameRef.current, bioRef.current]) {
      if (!el) continue;
      el.style.height = "auto";
      el.style.height = `${el.scrollHeight + 2}px`;
    }
  }, [tree.displayName, tree.bio, designTab]);

  // While a design tab is open, the editable page gives way to the real
  // rendered page (same HTML that gets published), so changes preview true
  // to life. Auto theme renders as whatever the Preview toggle shows.
  const pvRef = useRef<HTMLIFrameElement>(null);
  const previewHtml = showsPreview
    ? linkTreeToHtml(
        tree.theme === "system"
          ? { ...tree, theme: previewDark ? "dark" : "light" }
          : tree,
        `https://${displayAddress}`,
        undefined,
        tree.background === "image" && tree.bgUrl ? tree.bgUrl : undefined,
        tree.background === "image" && tree.bgDarkUrl
          ? tree.bgDarkUrl
          : undefined,
      )
    : "";
  const postPreview = () => {
    if (previewHtml) {
      pvRef.current?.contentWindow?.postMessage(
        { type: "preview-update", html: previewHtml },
        "*",
      );
    }
  };
  useEffect(postPreview, [previewHtml]);

  const autoImageOn =
    (tree.social?.autoImage ?? true) && priv.value.type === Type.LINK_TREE;
  useEffect(() => {
    if (!autoImageOn) {
      setOgPreview((prev) => {
        if (prev) URL.revokeObjectURL(prev);
        return "";
      });
      return;
    }
    let cancelled = false;
    const timeout = window.setTimeout(() => {
      renderOgImage(ensureLinkTree(priv.value.linkTree), displayAddress)
        .then((bytes) => {
          if (cancelled || !bytes) return;
          setOgPreview((prev) => {
            if (prev) URL.revokeObjectURL(prev);
            return URL.createObjectURL(
              new Blob([bytes as Uint8Array<ArrayBuffer>], {
                type: "image/png",
              }),
            );
          });
        })
        .catch(() => {});
    }, 400);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [
    autoImageOn,
    displayAddress,
    tree.displayName,
    tree.bio,
    tree.theme,
    tree.accent,
    tree.avatarUrl,
    tree.background,
    tree.bgUrl,
    tree.bgDarkUrl,
    tree.bgShade,
    tree.bgLighten,
    tree.coverTitle,
    tree.coverUrl,
    tree.coverFit,
    tree.coverHeight,
    tree.coverPos,
    tree.coverZoom,
    tree.corners,
    tree.social?.imageDark,
  ]);

  const updateTree = (nextTree: LinkTree) => {
    priv.value = {
      ...priv.value,
      type: Type.LINK_TREE,
      linkTree: nextTree,
    };
  };

  const pickBgImage = (key: "bgUrl" | "bgDarkUrl") => (e: Event) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    // An already-small web image (e.g. an optimized AVIF) is kept byte-for-
    // byte rather than re-encoded; anything bigger goes through compression.
    const small =
      /^image\/(avif|webp|jpeg|png|gif)$/.test(file.type) &&
      file.size <= 1024 * 1024;
    (small ? blobToDataUrl(file) : compressBg(file).then((img) => img.dataUrl))
      .then((dataUrl) => updateTree({ ...tree, [key]: dataUrl }))
      .catch((err) => onError((err as Error).message));
  };

  const social = tree.social ?? {};
  const updateSocial = (patch: Partial<SocialPreview>) => {
    updateTree({ ...tree, social: { ...social, ...patch } });
  };
  const pickOgImage = (e: Event) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    compressOgImage(file)
      .then((dataUrl) => updateSocial({ customImage: dataUrl }))
      .catch((err) => onError((err as Error).message));
  };

  const updateLink = (link: LinkItem) => {
    updateTree({
      ...tree,
      links: tree.links.map((current) =>
        current.id === link.id
          ? { ...link, href: normalizeLink(link).href }
          : current,
      ),
    });
  };

  const setFeatured = (id: string, featured: boolean) => {
    updateTree({
      ...tree,
      links: tree.links.map((link) => ({
        ...link,
        featured: featured && link.id === id ? true : undefined,
      })),
    });
  };

  const setIcon = (id: string, icon: string | undefined) => {
    const current = ensureLinkTree(priv.value.linkTree);
    updateTree({
      ...current,
      links: current.links.map((link) =>
        link.id === id ? { ...link, icon } : link,
      ),
    });
  };

  const addLinkOfKind = (kind: LinkKind) => {
    const link = defaultLinkItem(kind);
    updateTree({
      ...tree,
      links: [...tree.links, link],
    });
    setSelectedLinkId(link.id);
  };

  const moveLinkBy = (id: string, delta: number) => {
    const fromIndex = tree.links.findIndex((link) => link.id === id);
    const toIndex = fromIndex + delta;
    if (fromIndex < 0 || toIndex < 0 || toIndex >= tree.links.length) {
      return;
    }
    const nextLinks = [...tree.links];
    const [link] = nextLinks.splice(fromIndex, 1);
    nextLinks.splice(toIndex, 0, link);
    updateTree({ ...tree, links: nextLinks });
  };

  const removeLink = (id: string) => {
    updateTree({
      ...tree,
      links: tree.links.filter((link) => link.id !== id),
    });
    if (selectedLinkId === id) {
      setSelectedLinkId("");
    }
  };

  const moveLinkTo = (draggedId: string, targetId: string, after: boolean) => {
    if (!draggedId || draggedId === targetId) {
      return;
    }
    const fromIndex = tree.links.findIndex((link) => link.id === draggedId);
    const targetIndex = tree.links.findIndex((link) => link.id === targetId);
    if (fromIndex < 0 || targetIndex < 0) {
      return;
    }
    let toIndex = targetIndex + (after ? 1 : 0);
    // Removing the dragged item first shifts everything after it down one.
    if (fromIndex < toIndex) {
      toIndex -= 1;
    }
    const nextLinks = [...tree.links];
    const [link] = nextLinks.splice(fromIndex, 1);
    nextLinks.splice(toIndex, 0, link);
    updateTree({ ...tree, links: nextLinks });
  };

  const previewSwitch = tree.theme === "system" && (
    <div
      className="preview-mode preview-switch"
      role="group"
      aria-label="Preview appearance"
      title="Auto follows each visitor's device — check both looks here"
    >
      <span className="accent-row-label">Preview</span>
      <button
        type="button"
        className="quiet"
        aria-pressed={!previewDark}
        onClick={() => setPreviewDark(false)}
      >
        Light
      </button>
      <button
        type="button"
        className="quiet"
        aria-pressed={previewDark}
        onClick={() => setPreviewDark(true)}
      >
        Dark
      </button>
    </div>
  );

  return (
    <section className="live-editor" aria-label="Contact page editor">
      <div className="design-nav" role="group" aria-label="Design sections">
        <button
          type="button"
          aria-pressed={designTab === "editor"}
          onClick={() => setDesignTab("editor")}
        >
          Content
        </button>
        <button
          type="button"
          aria-pressed={designTab === "colors"}
          onClick={() => setDesignTab("colors")}
        >
          Colors
        </button>
        <button
          type="button"
          aria-pressed={designTab === "style"}
          onClick={() => setDesignTab("style")}
        >
          Style
        </button>
        <button
          type="button"
          aria-pressed={designTab === "background"}
          onClick={() => setDesignTab("background")}
        >
          Background
        </button>
        <button
          type="button"
          aria-pressed={designTab === "social"}
          onClick={() => setDesignTab("social")}
        >
          Sharing
        </button>
      </div>

      {designTab === "editor" && previewSwitch}
      {designTab === "editor" && (
        <div className="preview-shell" style={previewShellStyle}>
          <div
            className={`live-page theme-${tree.theme || "system"} ${(tree.theme || "system") === "system" && previewDark ? "pv-dark" : ""} avatar-${tree.avatarShape ?? "circle"} btn-${tree.buttons ?? "soft"} ${tree.coverTitle && avatarImageSrc(tree.coverUrl) ? "cover-title" : ""} ${accentPair(tree.accent) ? "accent-custom" : ""} ${tree.background === "image" && tree.bgUrl ? "has-bg-image" : ""}`}
            style={{
              fontFamily: fontStack(tree),
              "--radius": cornerRadius(tree),
              "--avatar-radius": avatarRadius(tree),
              "--pv-btn-alpha": String(clampBtnAlpha(tree.btnAlpha)),
              "--pv-btn-blur": `${clampBtnBlur(tree.btnBlur)}px`,
              // Image backgrounds go through CSS vars so both derived variants
              // preview: the light one lightened by bgLighten%, and the dark one
              // (the custom dark image if any, darkened by bgShade%) — matching
              // what the published page lays over each variant.
              ...(tree.background === "image" && tree.bgUrl
                ? {
                    "--pv-bg-light": `url("${tree.bgUrl}")`,
                    ...(tree.bgDarkUrl
                      ? { "--pv-bg-dark": `url("${tree.bgDarkUrl}")` }
                      : {}),
                    "--pv-shade": String(clampShade(tree.bgShade) / 100),
                    "--pv-lighten": String(clampLighten(tree.bgLighten) / 100),
                  }
                : {
                    background: pageBackground(tree, "--pv-accent", "--pv-bg"),
                  }),
              ...(accentPair(tree.accent)
                ? {
                    "--pv-a-light": accentPair(tree.accent)!.light,
                    "--pv-a-dark": accentPair(tree.accent)!.dark,
                  }
                : {}),
            }}
          >
            <div className="live-profile">
              <CoverEditor
                tree={tree}
                updateTree={updateTree}
                onError={onError}
              />
              <AvatarEditor
                tree={tree}
                updateTree={updateTree}
                onError={onError}
              />
              <textarea
                className="live-name"
                aria-label="Name"
                rows={1}
                ref={nameRef}
                value={tree.displayName}
                placeholder="Ada Lovelace"
                onInput={(e) =>
                  updateTree({
                    ...tree,
                    // One logical line that wraps like the published heading —
                    // newlines (typed or pasted) become spaces.
                    displayName: (
                      e.target as HTMLTextAreaElement
                    ).value.replace(/\s*[\r\n]+\s*/g, " "),
                  })
                }
              ></textarea>
              <input
                className="live-status"
                aria-label="Status line"
                type="text"
                value={tree.status ?? ""}
                maxLength={60}
                placeholder="🟢 Status (optional)"
                onInput={(e) =>
                  updateTree({
                    ...tree,
                    status: (e.target as HTMLInputElement).value,
                  })
                }
              />
              <textarea
                className="live-bio"
                aria-label="Short description"
                rows={1}
                ref={bioRef}
                value={tree.bio}
                placeholder="Mathematician · first computer programmer"
                onInput={(e) =>
                  updateTree({
                    ...tree,
                    bio: (e.target as HTMLTextAreaElement).value,
                  })
                }
              ></textarea>
            </div>

            <div
              className={`vcard-inplace${tree.showVcard !== false ? "" : " is-off"}`}
            >
              <label className="show-toggle vcard-inplace-toggle">
                <input
                  type="checkbox"
                  checked={tree.showVcard !== false}
                  onChange={(e) =>
                    updateTree({
                      ...tree,
                      showVcard: (e.target as HTMLInputElement).checked,
                    })
                  }
                />
                <span className="sr-only">Show a "Save contact" button</span>
              </label>
              <span className="vcard-button-preview">Save contact</span>
            </div>
            {tree.showVcard !== false && !vcardEligible(tree) && (
              <p className="help vcard-inplace-help">
                Lets visitors download a contact card (.vcf). It appears once
                the page has a name and a shown phone or email.
              </p>
            )}

            <div className="editable-links" aria-label="Contact buttons">
              {tree.links.length > 0 ? (
                tree.links.map((link, index) => (
                  <EditableLink
                    key={link.id}
                    link={link}
                    index={index}
                    total={tree.links.length}
                    updateLink={updateLink}
                    setFeatured={setFeatured}
                    setIcon={setIcon}
                    onError={onError}
                    removeLink={() => removeLink(link.id)}
                    moveTo={moveLinkTo}
                    moveBy={moveLinkBy}
                    dragging={draggingId === link.id}
                    setDragging={setDraggingId}
                    dropTarget={
                      dragOverId === link.id && draggingId !== link.id
                    }
                    dropAfter={dragAfter}
                    setDragOver={setDragOver}
                    selected={selectedLinkId === link.id}
                    setSelected={setSelectedLinkId}
                  />
                ))
              ) : (
                <div className="empty-list">
                  <p>No contact buttons yet.</p>
                </div>
              )}
            </div>

            <div className="add-section">
              <button
                type="button"
                className="secondary add-open"
                popovertarget="addMenu"
              >
                <span className="add-link-plus" aria-hidden="true">
                  +{" "}
                </span>
                Add row
              </button>
            </div>

            <div
              popover="auto"
              id="addMenu"
              className="popover-panel add-popover"
            >
              <div className="popover-heading">
                <h2>Add to your page</h2>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="Close"
                  onClick={() =>
                    document.getElementById("addMenu")?.hidePopover()
                  }
                >
                  <span aria-hidden="true">×</span>
                </button>
              </div>
              {addGroups.map((group) => (
                <div className="add-group" key={group.label}>
                  <span className="add-label">{group.label}</span>
                  <div className="add-chips">
                    {group.kinds.map((kind) => (
                      <button
                        type="button"
                        className="add-link-item"
                        key={kind}
                        onClick={() => {
                          document.getElementById("addMenu")?.hidePopover();
                          addLinkOfKind(kind);
                        }}
                      >
                        <span className="add-link-plus" aria-hidden="true">
                          +
                        </span>
                        {kindLabels[kind]}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <PreviewResizeHandle
            width={previewWidth}
            commit={commitPreviewWidth}
          />
        </div>
      )}

      {designTab === "colors" && (
        <fieldset className="theme-picker">
          <legend className="sr-only">Colors</legend>
          <div className="theme-row">
            <select
              className="theme-select"
              aria-label="Theme"
              title="Auto follows each visitor's device"
              value={tree.theme}
              onChange={(e) =>
                updateTree({
                  ...tree,
                  theme: (e.target as HTMLSelectElement)
                    .value as LinkTree["theme"],
                })
              }
            >
              <option value="system">Auto</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </div>
          <div className="accent-row">
            <span className="sr-only">Accent</span>
            <label className="accent-choice" title="Theme default">
              <input
                type="radio"
                name="accent"
                checked={!accentPair(tree.accent)}
                onChange={() => updateTree({ ...tree, accent: "" })}
              />
              <span
                className="accent-dot"
                style={{ background: themeAccentDefaults[tree.theme] }}
              ></span>
              <span className="sr-only">Theme default</span>
            </label>
            {Object.entries(legacyAccents).map(([name, value]) => {
              const pair = accentPair(value)!;
              return (
                <label
                  className="accent-choice"
                  key={name}
                  title={name[0].toUpperCase() + name.slice(1)}
                >
                  <input
                    type="radio"
                    name="accent"
                    checked={
                      (legacyAccents[tree.accent ?? ""] ?? tree.accent) ===
                      value
                    }
                    onChange={() => updateTree({ ...tree, accent: value })}
                  />
                  <span
                    className="accent-dot"
                    style={{
                      background: `linear-gradient(135deg, ${pair.light} 50%, ${pair.dark} 50%)`,
                    }}
                  ></span>
                  <span className="sr-only">{name}</span>
                </label>
              );
            })}
            <div className="accent-wheel-row">
              <AccentWheel
                value={tree.accent ?? ""}
                onChange={(accent) => updateTree({ ...tree, accent })}
              />
            </div>
          </div>
        </fieldset>
      )}

      {designTab === "style" && (
        <fieldset className="style-picker">
          <legend className="sr-only">Style</legend>
          <div className="style-grid">
            <label className="field stack">
              <span>Font</span>
              <select
                value={tree.font ?? "system"}
                onChange={(e) =>
                  updateTree({
                    ...tree,
                    font: (e.target as HTMLSelectElement).value as FontChoice,
                  })
                }
              >
                <option value="system">System</option>
                <option value="sans">Sans</option>
                <option value="serif">Serif</option>
                <option value="mono">Mono</option>
                <option value="rounded">Rounded</option>
              </select>
            </label>
            <label className="field stack">
              <span>Buttons</span>
              <select
                value={tree.buttons ?? "soft"}
                onChange={(e) =>
                  updateTree({
                    ...tree,
                    buttons: (e.target as HTMLSelectElement)
                      .value as ButtonStyle,
                  })
                }
              >
                <option value="soft">Soft</option>
                <option value="outline">Outline</option>
                <option value="filled">Filled</option>
              </select>
            </label>
            <label className="field stack">
              <span>Corners</span>
              <select
                value={tree.corners ?? "rounded"}
                onChange={(e) =>
                  updateTree({
                    ...tree,
                    corners: (e.target as HTMLSelectElement).value as Corners,
                  })
                }
              >
                <option value="rounded">Rounded</option>
                <option value="sharp">Sharp</option>
                <option value="pill">Pill</option>
              </select>
            </label>
            <label className="field stack">
              <span>Photo shape</span>
              <select
                value={tree.avatarShape ?? "circle"}
                onChange={(e) =>
                  updateTree({
                    ...tree,
                    avatarShape: (e.target as HTMLSelectElement)
                      .value as AvatarShape,
                  })
                }
              >
                <option value="circle">Circle</option>
                <option value="rounded">Rounded square</option>
              </select>
            </label>
          </div>
          <div className="style-fx">
            <label className="field-range">
              <span>Button transparency</span>
              <input
                type="range"
                min={0}
                max={90}
                step={5}
                value={100 - clampBtnAlpha(tree.btnAlpha)}
                onInput={(e) =>
                  updateTree({
                    ...tree,
                    btnAlpha:
                      100 - Number((e.target as HTMLInputElement).value),
                  })
                }
              />
            </label>
            <label className="field-range">
              <span>Blur behind</span>
              <input
                type="range"
                min={0}
                max={24}
                step={2}
                value={clampBtnBlur(tree.btnBlur)}
                onInput={(e) =>
                  updateTree({
                    ...tree,
                    btnBlur: Number((e.target as HTMLInputElement).value),
                  })
                }
              />
            </label>
          </div>
        </fieldset>
      )}

      {designTab === "background" && (
        <fieldset className="style-picker">
          <legend className="sr-only">Background</legend>
          {/* First pick the background, then tune the light/dark variant
              being previewed. */}
          <div className="bg-kind-row" role="group" aria-label="Background">
            {(
              [
                ["none", "None"],
                ["gradient", "Gradient"],
                ["dots", "Dots"],
                ["grid", "Grid"],
                ["image", "Image"],
              ] as [Background, string][]
            ).map(([kind, label]) => (
              <button
                type="button"
                className="quiet"
                key={kind}
                aria-pressed={(tree.background ?? "none") === kind}
                onClick={() => updateTree({ ...tree, background: kind })}
              >
                {label}
              </button>
            ))}
          </div>
          {tree.background === "image" && (
            <div className="cover-editor-actions">
              <label className="button-link secondary">
                {tree.bgUrl ? "Replace image" : "Add an image"}
                <input
                  type="file"
                  accept="image/*"
                  className="sr-only"
                  onChange={pickBgImage("bgUrl")}
                />
              </label>
              {tree.bgUrl && (
                <button
                  type="button"
                  className="secondary"
                  onClick={() =>
                    updateTree({ ...tree, bgUrl: "", bgDarkUrl: "" })
                  }
                >
                  Remove
                </button>
              )}
            </div>
          )}
          {tree.background === "image" && tree.bgUrl && (
            <div className="bg-variant">
              {tree.background === "image" &&
                tree.bgUrl &&
                (tree.theme === "dark" ||
                (tree.theme === "system" && previewDark) ? (
                  <>
                    <label className="field-range">
                      <span>Darken by</span>
                      <input
                        type="range"
                        min={0}
                        max={90}
                        step={5}
                        value={clampShade(tree.bgShade)}
                        onInput={(e) =>
                          updateTree({
                            ...tree,
                            bgShade: Number(
                              (e.target as HTMLInputElement).value,
                            ),
                          })
                        }
                      />
                    </label>
                    <div className="cover-editor-actions">
                      <label className="button-link secondary">
                        {tree.bgDarkUrl
                          ? "Replace dark image"
                          : "Or upload a separate dark image"}
                        <input
                          type="file"
                          accept="image/*"
                          className="sr-only"
                          onChange={pickBgImage("bgDarkUrl")}
                        />
                      </label>
                      {tree.bgDarkUrl && (
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => updateTree({ ...tree, bgDarkUrl: "" })}
                        >
                          Remove dark image
                        </button>
                      )}
                    </div>
                  </>
                ) : (
                  <label className="field-range">
                    <span>Lighten by</span>
                    <input
                      type="range"
                      min={0}
                      max={90}
                      step={5}
                      value={clampLighten(tree.bgLighten)}
                      onInput={(e) =>
                        updateTree({
                          ...tree,
                          bgLighten: Number(
                            (e.target as HTMLInputElement).value,
                          ),
                        })
                      }
                    />
                  </label>
                ))}
            </div>
          )}
        </fieldset>
      )}

      {designTab === "social" && (
        <div className="social-preview-fields">
          <label className="field stack favicon-field">
            <span>Favicon emoji</span>
            <input
              type="text"
              value={tree.favicon ?? ""}
              maxLength={8}
              placeholder="e.g. ☕"
              onInput={(e) =>
                updateTree({
                  ...tree,
                  favicon: (e.target as HTMLInputElement).value,
                })
              }
            />
            <p className="help">Shown in the browser tab.</p>
          </label>
          <span className="field-label">Preview</span>
          <div className="panel-group">
            <label className="show-toggle">
              <input
                type="radio"
                name="og-image-mode"
                checked={social.autoImage ?? true}
                onChange={() => updateSocial({ autoImage: true })}
              />
              <span>Automatic preview image</span>
            </label>
            <label className="show-toggle">
              <input
                type="radio"
                name="og-image-mode"
                checked={!(social.autoImage ?? true)}
                onChange={() => updateSocial({ autoImage: false })}
              />
              <span>Custom preview image</span>
            </label>
          </div>
          {(social.autoImage ?? true) && tree.theme !== "dark" && (
            <div
              className="preview-mode"
              role="group"
              aria-label="Preview image appearance"
            >
              <span className="accent-row-label">Looks</span>
              <button
                type="button"
                className="quiet"
                aria-pressed={!social.imageDark}
                onClick={() => updateSocial({ imageDark: false })}
              >
                Light
              </button>
              <button
                type="button"
                className="quiet"
                aria-pressed={Boolean(social.imageDark)}
                onClick={() => updateSocial({ imageDark: true })}
              >
                Dark
              </button>
            </div>
          )}
          {(social.autoImage ?? true) && ogPreview && (
            <img
              className="og-preview"
              src={ogPreview}
              alt="Preview image that will be published"
              width={1200}
              height={630}
            />
          )}
          {!(social.autoImage ?? true) && (
            <>
              {social.customImage && (
                <img
                  className="og-preview"
                  src={social.customImage}
                  alt="Custom preview image that will be published"
                  width={1200}
                  height={630}
                />
              )}
              <div className="cover-editor-actions">
                <label className="button-link secondary">
                  {social.customImage ? "Replace image" : "Upload an image"}
                  <input
                    type="file"
                    accept="image/*"
                    className="sr-only"
                    onChange={pickOgImage}
                  />
                </label>
                {social.customImage && (
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => updateSocial({ customImage: "" })}
                  >
                    Remove
                  </button>
                )}
              </div>
              {!social.customImage && (
                <p className="help">
                  Cropped to 1200×630 and served with your page. Until you add
                  one, links share without an image.
                </p>
              )}
            </>
          )}
          <label className="field stack">
            <span>Preview title</span>
            <input
              type="text"
              value={social.title ?? ""}
              placeholder={tree.displayName.trim() || "Ada Lovelace"}
              onInput={(e) =>
                updateSocial({ title: (e.target as HTMLInputElement).value })
              }
            />
          </label>
          <label className="field stack">
            <span>Preview description</span>
            <input
              type="text"
              value={social.description ?? ""}
              placeholder={
                tree.bio.trim() || "Mathematician · first computer programmer"
              }
              onInput={(e) =>
                updateSocial({
                  description: (e.target as HTMLInputElement).value,
                })
              }
            />
          </label>
          {(() => {
            // Sign-in profile email: only a choice when more than one email is
            // shown; with one (or none) there's nothing to pick.
            const emails = activeValidLinks(tree).filter(
              (l) => l.item.kind === "email",
            );
            if (emails.length < 2) return null;
            const chosen = emails.some((l) => l.item.id === tree.profileEmailId)
              ? tree.profileEmailId
              : emails[0].item.id;
            return (
              <>
                <span className="field-label">Sign-in</span>
                <label className="field stack">
                  <span>Profile email</span>
                  <select
                    value={chosen}
                    onChange={(e) =>
                      updateTree({
                        ...tree,
                        profileEmailId: (e.target as HTMLSelectElement).value,
                      })
                    }
                  >
                    {emails.map((l) => (
                      <option key={l.item.id} value={l.item.id}>
                        {l.href.replace(/^mailto:/i, "").split("?")[0]}
                      </option>
                    ))}
                  </select>
                  <p className="help">
                    Which address an app receives when someone signs in with
                    your page and allows the email permission.
                  </p>
                </label>
              </>
            );
          })()}
        </div>
      )}

      {showsPreview && (
        <>
          {previewSwitch}
          <div className="preview-shell" style={previewShellStyle}>
            <iframe
              className="live-preview"
              title="Page preview"
              ref={pvRef}
              onLoad={postPreview}
              srcdoc={previewBootstrap}
            ></iframe>
            <PreviewResizeHandle
              width={previewWidth}
              commit={commitPreviewWidth}
            />
          </div>
        </>
      )}
    </section>
  );
}
