import { copyRichSignature, signatureHtml, signatureText } from "../render";
import { LinkTree } from "../types";
import { useState } from "preact/hooks";

export function EmailSignaturePopover({
  tree,
  url,
  onError,
}: {
  tree: LinkTree;
  url: string;
  onError: (message: string) => void;
}) {
  const [copiedKind, setCopiedKind] = useState<
    "" | "rich" | "richPlain" | "plain"
  >("");
  const html = signatureHtml(tree, url);
  const text = signatureText(tree, url);

  const flashCopied = (kind: "rich" | "richPlain" | "plain") => {
    setCopiedKind(kind);
    window.setTimeout(() => setCopiedKind(""), 1800);
  };

  return (
    <div
      popover="auto"
      id="emailSignature"
      className="popover-panel signature-popover"
    >
      <div className="popover-heading">
        <h2>Email signature</h2>
        <button
          type="button"
          className="icon-button"
          aria-label="Close"
          onClick={() =>
            document.getElementById("emailSignature")?.hidePopover()
          }
        >
          <span aria-hidden="true">×</span>
        </button>
      </div>
      <div
        className="signature-preview"
        role="region"
        aria-label="Signature preview"
        dangerouslySetInnerHTML={{ __html: html }}
      ></div>
      <p className="help">
        Copy, then paste into your email app's signature settings.
      </p>
      <div className="popover-actions">
        <button
          type="button"
          aria-live="polite"
          onClick={() => {
            copyRichSignature(html, text)
              .then((rich) => flashCopied(rich ? "rich" : "richPlain"))
              .catch((e) => onError(e.message));
          }}
        >
          {copiedKind === "rich"
            ? "Copied ✓"
            : copiedKind === "richPlain"
              ? "Copied as plain text"
              : "Copy signature"}
        </button>
        <button
          type="button"
          className="secondary"
          aria-live="polite"
          onClick={() => {
            navigator.clipboard
              .writeText(text)
              .then(() => flashCopied("plain"))
              .catch((e) => onError(e.message));
          }}
        >
          {copiedKind === "plain" ? "Copied ✓" : "Copy plain text"}
        </button>
      </div>
    </div>
  );
}
