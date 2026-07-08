export const subtle = window.crypto.subtle;
export const textEncoder = new TextEncoder();

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function publicPageUrl(path: string): string {
  return `https://found.as/${encodePath(path)}`;
}

// pageSubUrl is a root-relative URL for a page's subresource. It resolves
// same-origin on both found.as/<path>/<sub> and custom-domain/<path>/<sub>, so a
// custom-domain page loads its own assets (backgrounds, etc.) without a
// third-party request back to found.as.
export function pageSubUrl(path: string, sub: string, version: string): string {
  return `/${encodePath(path)}/${sub}?v=${version}`;
}

export function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

export function splitGraphemes(value: string): string[] {
  if (typeof Intl !== "undefined" && Intl.Segmenter) {
    return [
      ...new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(
        value,
      ),
    ].map((part) => part.segment);
  }
  return [...value];
}

export function downloadFile(filename: string, blob: Blob): void {
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

// Boots an empty iframe document that swaps in page HTML posted from the
// editor, so live tweaks update the preview without reloading the frame.
export const previewBootstrap = `<html><head><script>
window.addEventListener('message', (e) => {
  if (e.data?.type === 'preview-update') {
    const parser = new DOMParser();
    const doc = parser.parseFromString(e.data.html, 'text/html');
    Array.from(doc.documentElement.attributes).forEach(attr => {
      document.documentElement.setAttribute(attr.name, attr.value);
    });
    document.documentElement.innerHTML = e.data.html;
  }
})
</script></head><body></body></html>`;
