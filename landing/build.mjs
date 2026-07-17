#!/usr/bin/env node
// Renders landing/template.html into one full HTML document per language by
// inlining the strings from landing/<lang>.json. String values are raw HTML
// fragments (entities and inline markup included) so translations can keep
// emphasis spans and links. publish.mjs publishes the result; run this file
// directly to write previews: node landing/build.mjs [outdir] (default
// landing/out, gitignored).
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

export const landingLangs = ["en", "fr", "de", "es", "it"];
const navLabels = { en: "EN", fr: "FR", de: "DE", es: "ES", it: "IT" };

// The selector marks the current language and labels the others with their
// own lang for assistive tech.
function langNav(current) {
  return landingLangs
    .map((tag) => {
      const attrs =
        tag === current
          ? ' aria-current="true"'
          : ` lang="${tag}" hreflang="${tag}"`;
      return `<a href="/?${tag}"${attrs}>${navLabels[tag]}</a>`;
    })
    .join("\n        ");
}

export async function renderLandings() {
  const template = await readFile(join(HERE, "template.html"), "utf8");
  const out = {};
  for (const lang of landingLangs) {
    const strings = JSON.parse(
      await readFile(join(HERE, `${lang}.json`), "utf8"),
    );
    const extra = new Set(Object.keys(strings));
    strings.lang = lang;
    // Each variant is its own canonical; hreflang alternates tie them together.
    strings.canonicalUrl =
      lang === "en" ? "https://found.as/" : `https://found.as/?${lang}`;
    strings.langNav = langNav(lang);
    out[lang] = template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
      if (!(key in strings)) {
        throw new Error(`${lang}.json: missing string "${key}"`);
      }
      extra.delete(key);
      return strings[key];
    });
    if (extra.size) {
      throw new Error(
        `${lang}.json: unused strings (typo?): ${[...extra].join(", ")}`,
      );
    }
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const outDir = process.argv[2] ?? join(HERE, "out");
  await mkdir(outDir, { recursive: true });
  const rendered = await renderLandings();
  for (const [lang, html] of Object.entries(rendered)) {
    await writeFile(join(outDir, `${lang}.html`), html);
  }
  console.log(`✓ wrote ${Object.keys(rendered).length} pages to ${outDir}`);
}
