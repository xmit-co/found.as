import { lang, setLang, t, uiLanguages } from "../i18n";

// Compact language selector: a native select showing each language under its
// own name. Changing it persists the choice and reloads the app.
export function LangPicker() {
  return (
    <select
      className="lang-picker"
      aria-label={t("Language")}
      value={lang}
      onChange={(e) => setLang((e.target as HTMLSelectElement).value)}
    >
      {Object.entries(uiLanguages).map(([tag, label]) => (
        <option key={tag} value={tag}>
          {label}
        </option>
      ))}
    </select>
  );
}
