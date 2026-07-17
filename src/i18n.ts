import type { ComponentChildren } from "preact";
import fr from "./locales/fr";
import de from "./locales/de";
import es from "./locales/es";
import it from "./locales/it";

// The editor's UI languages: tags match the landing page's ?tag variants;
// labels are each language's own name (never translated).
export const uiLanguages: Record<string, string> = {
  en: "English",
  fr: "Français",
  de: "Deutsch",
  es: "Español",
  it: "Italiano",
};

const dicts: Record<string, Record<string, string>> = { fr, de, es, it };

export const LANG_KEY = "found.as:lang";

// A bare ?fr-style query key, as used by the landing page's language variants;
// its links carry the visitor's choice here the same way.
function urlLang(): string | null {
  const params = new URLSearchParams(location.search);
  for (const tag of Object.keys(uiLanguages)) {
    if (params.has(tag)) return tag;
  }
  return null;
}

function detectLang(): string {
  // The URL key is an explicit choice (made on the landing page): it wins over
  // this device's stored preference and replaces it for future visits.
  const fromUrl = urlLang();
  if (fromUrl) {
    try {
      localStorage.setItem(LANG_KEY, fromUrl);
    } catch {
      // storage blocked — still honored for this visit
    }
    return fromUrl;
  }
  try {
    const saved = localStorage.getItem(LANG_KEY);
    if (saved && saved in uiLanguages) return saved;
  } catch {
    // storage blocked — fall through to browser language
  }
  for (const cand of navigator.languages ?? [navigator.language]) {
    const base = cand?.slice(0, 2).toLowerCase();
    if (base && base in uiLanguages) return base;
  }
  return "en";
}

export const lang = detectLang();
const dict = dicts[lang];

// t returns the UI string for the current language. The English string is the
// key; untranslated (or English-session) strings pass through unchanged.
// {name} tokens are replaced from subs after lookup, so dictionaries translate
// whole templates: t("Publish to {host}", { host }).
export function t(s: string, subs?: Record<string, string>): string {
  let out = dict?.[s] ?? s;
  if (subs) {
    for (const [k, v] of Object.entries(subs)) {
      out = out.replaceAll(`{${k}}`, v);
    }
  }
  return out;
}

// tx is t for JSX: after translation, {name} slots are replaced with the given
// nodes (markup included), so sentences keep their markup while each language
// controls its own word order. Returns children to splice into JSX.
export function tx(
  s: string,
  slots: Record<string, ComponentChildren>,
): ComponentChildren[] {
  return t(s)
    .split(/\{(\w+)\}/g)
    .map((part, i) => (i % 2 ? (slots[part] ?? `{${part}}`) : part));
}

// setLang persists the choice for this device and reloads so every rendered
// string — including ones captured in module state — comes back translated.
export function setLang(next: string): void {
  if (next === lang || !(next in uiLanguages)) {
    return;
  }
  try {
    localStorage.setItem(LANG_KEY, next);
  } catch {
    // storage blocked — the reload will still fall back to browser language
  }
  // Drop any ?fr-style key a landing-page link left in the URL: it would
  // out-rank the new choice on reload.
  if (urlLang()) {
    const params = new URLSearchParams(location.search);
    for (const tag of Object.keys(uiLanguages)) {
      params.delete(tag);
    }
    const query = params.toString();
    history.replaceState(
      null,
      "",
      location.pathname + (query ? `?${query}` : "") + location.hash,
    );
  }
  location.reload();
}
