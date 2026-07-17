import { RememberedPage, loadMainAddress } from "../storage";
import { BuilderMode, Type } from "../types";
import { useState } from "preact/hooks";
import { LangPicker } from "./LangPicker";
import { t } from "../i18n";

export function BuilderModePicker({
  mode,
  setMode,
  advancedType,
  setAdvancedType,
}: {
  mode: BuilderMode;
  setMode: (mode: BuilderMode) => void;
  advancedType: Type;
  setAdvancedType: (type: Type) => void;
}) {
  return (
    <section className="intent-row" aria-label={t("Page type")}>
      <span className="accent-row-label">{t("Page type")}</span>
      <label
        className="intent-choice"
        title={t("Links for web, email, social, phone, and more.")}
      >
        <input
          type="radio"
          name="builder-mode"
          value="contact"
          checked={mode === "contact"}
          onChange={() => setMode("contact")}
        />
        <span>{t("Contact page")}</span>
      </label>
      <label
        className="intent-choice"
        title={t("Redirect, markdown page, HTML page, or file.")}
      >
        <input
          type="radio"
          name="builder-mode"
          value="advanced"
          checked={mode === "advanced"}
          onChange={() => setMode("advanced")}
        />
        <span>{t("Advanced")}</span>
      </label>
      {mode === "advanced" && (
        <AdvancedModePicker value={advancedType} setValue={setAdvancedType} />
      )}
    </section>
  );
}

export function AdvancedModePicker({
  value,
  setValue,
}: {
  value: Type;
  setValue: (type: Type) => void;
}) {
  const modes: { type: Type; label: string; description: string }[] = [
    {
      type: Type.REDIR,
      label: t("Redirect"),
      description: t("Send visitors to one web address."),
    },
    {
      type: Type.MARKDOWN_PAGE,
      label: t("Markdown"),
      description: t("Write a simple page with Markdown."),
    },
    {
      type: Type.HTML_PAGE,
      label: t("HTML"),
      description: t("Publish a custom HTML page."),
    },
    {
      type: Type.BYTES,
      label: t("File"),
      description: t("Host one file up to 5MB."),
    },
  ];

  return (
    <div
      className="design-nav advanced-nav"
      role="group"
      aria-label={t("Advanced format")}
    >
      {modes.map((mode) => (
        <button
          type="button"
          key={mode.type}
          aria-pressed={value === mode.type}
          title={mode.description}
          onClick={() => setValue(mode.type)}
        >
          {mode.label}
        </button>
      ))}
    </div>
  );
}

export function modeSummary(type: Type): string {
  if (type === Type.LINK_TREE) return "Contact page";
  if (type === Type.REDIR) return "Redirect";
  if (type === Type.MARKDOWN_PAGE) return "Markdown page";
  if (type === Type.HTML_PAGE) return "HTML page";
  return "File";
}

export function SetupPanel({
  path,
  setPath,
  pw,
  setPw,
  working,
  pwStatus,
  pathIsNew,
  remember,
  setRemember,
  remembered,
  openRemembered,
  forgetRemembered,
  onContinue,
}: {
  path: string;
  setPath: (path: string) => void;
  pw: string;
  setPw: (pw: string) => void;
  working: boolean;
  pwStatus: boolean | undefined;
  pathIsNew: boolean;
  remember: boolean;
  setRemember: (v: boolean) => void;
  remembered: RememberedPage[];
  openRemembered: (path: string) => void;
  forgetRemembered: (path: string) => void;
  onContinue: () => void;
}) {
  const [revealPw, setRevealPw] = useState(false);
  const hasPath = path.trim().length > 0;
  const canContinue = pwStatus === true && !working;
  const isNew = pwStatus === true && pathIsNew;
  const isExisting = pwStatus === true && !pathIsNew;

  const availability = !hasPath
    ? null
    : working
      ? { className: "help", text: t("Checking availability…") }
      : isNew
        ? {
            className: "help available-text",
            text: t("found.as/{path} is available.", { path: path.trim() }),
          }
        : isExisting
          ? {
              className: "help",
              text: t(
                "This address already exists — password unlocked. Continue to edit it.",
              ),
            }
          : pwStatus === false
            ? {
                className: "help error-text",
                text: t(
                  "This address exists. Enter its password to edit, or pick another address.",
                ),
              }
            : null;

  // Capitals and punctuation work, but make a link harder to type and share
  // (and the address is case-sensitive), so nudge toward a clean slug.
  const pathTrimmed = path.trim();
  const pathDiscouraged = pathTrimmed !== "" && /[^a-z0-9/-]/.test(pathTrimmed);

  return (
    <section className="setup-panel" aria-labelledby="setup-title">
      <div className="setup-copy">
        <div className="setup-topline">
          <p className="eyebrow">found.as</p>
          <LangPicker />
        </div>
        <h1 id="setup-title">{t("Online in seconds")}</h1>
        <p>{t("Pick an address and a password. No account, no cookies.")}</p>
      </div>
      <form
        className="setup-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (canContinue) {
            onContinue();
          }
        }}
      >
        <label className="field stack">
          <span>{t("Your address")}</span>
          <span className="path-field">
            <span className="path-prefix">found.as/</span>
            <input
              type="text"
              aria-label={t("Page path")}
              maxLength={64}
              value={path}
              autoComplete="off"
              autoCapitalize="off"
              spellcheck={false}
              aria-describedby={availability ? "setup-path-status" : undefined}
              // The raw value salts the key and names the page, so an
              // invisible trailing space would silently address a different
              // page — drop whitespace instead of letting it in.
              onInput={(e) =>
                setPath(
                  (e.target as HTMLInputElement).value.replace(/\s+/g, ""),
                )
              }
            />
          </span>
        </label>
        {pathDiscouraged && (
          <p className="help warning-text">
            {t(
              "Lowercase letters, numbers and hyphens make the best address — capitals and special characters are harder to type and share.",
            )}
          </p>
        )}
        {availability && (
          <p id="setup-path-status" className={availability.className}>
            {availability.text}
          </p>
        )}
        <label className="field stack">
          <span>{isExisting ? t("Page password") : t("Choose a password")}</span>
          <span className="path-field reveal-field">
            <input
              type={revealPw ? "text" : "password"}
              value={pw}
              autoComplete={isExisting ? "current-password" : "new-password"}
              placeholder={
                pwStatus === false
                  ? t("Enter the existing password")
                  : t("Use this to edit later")
              }
              aria-invalid={pwStatus === false}
              onInput={(e) => setPw((e.target as HTMLInputElement).value)}
            />
            <button
              type="button"
              className="reveal-toggle"
              aria-pressed={revealPw}
              onClick={() => setRevealPw((v) => !v)}
            >
              {revealPw ? t("Hide") : t("Show")}
            </button>
          </span>
        </label>
        {isNew && pw === "" && (
          <p className="help warning-text">
            {t(
              "Blank password — anyone who opens this editor address can change your page.",
            )}
          </p>
        )}
        <p className="help recovery-note">
          {t(
            "There is no password reset. Once you're in, save the recovery kit from the menu — it keeps your address and password somewhere safe.",
          )}
        </p>
        {pwStatus === true && (
          <>
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
                  "Saves this page's key in this browser so it opens without the password. Only on a device you trust.",
                )}
              </p>
            )}
          </>
        )}
        <div className="action-row">
          <button type="submit" disabled={!canContinue}>
            {isExisting ? t("Edit page") : t("Create page")}
          </button>
        </div>
      </form>
      {remembered.length > 0 && (
        <div className="remembered-pages">
          <p className="remembered-title">{t("Remembered on this device")}</p>
          <ul>
            {remembered.map((r) => (
              <li key={r.path}>
                <button
                  type="button"
                  className="remembered-open"
                  onClick={() => openRemembered(r.path)}
                >
                  {loadMainAddress(r.path) ?? `/${r.path}`}
                </button>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => forgetRemembered(r.path)}
                >
                  {t("Forget")}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
