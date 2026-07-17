import { copyRichSignature, signatureHtml, signatureText } from "../render";
import { LinkTree } from "../types";
import { useState } from "preact/hooks";
import { t } from "../i18n";

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
        <h2>{t("Email signature")}</h2>
        <button
          type="button"
          className="icon-button"
          aria-label={t("Close")}
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
        aria-label={t("Signature preview")}
        dangerouslySetInnerHTML={{ __html: html }}
      ></div>
      <p className="help">
        {t("Copy, then paste into your email app's signature settings.")}
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
            ? t("Copied ✓")
            : copiedKind === "richPlain"
              ? t("Copied as plain text")
              : t("Copy signature")}
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
          {copiedKind === "plain" ? t("Copied ✓") : t("Copy plain text")}
        </button>
      </div>
    </div>
  );
}
