import {
  accentLightL,
  accentMaxChroma,
  accentPair,
  oklchToHex,
  parseAccent,
} from "../color";
import { useRef } from "preact/hooks";
import { t } from "../i18n";

// The wheel face: hue around the rim, chroma fading to gray at the center —
// OKLCH at the light theme's accent lightness, precomputed to hex so the
// gradient matches oklchToHex's gamut clipping exactly.
export const accentWheelFace = [
  `radial-gradient(closest-side, ${oklchToHex(accentLightL, 0, 0)}, transparent)`,
  `conic-gradient(${Array.from({ length: 37 }, (_, i) =>
    oklchToHex(accentLightL, accentMaxChroma, i * 10),
  ).join(", ")})`,
].join(", ");

export function AccentWheel({
  value,
  onChange,
}: {
  value: string;
  onChange: (accent: string) => void;
}) {
  const selected = parseAccent(value);
  const dragging = useRef(false);

  const pick = (e: PointerEvent) => {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;
    // Angle clockwise from 12 o'clock, matching the conic gradient.
    const hue = Math.round(((Math.atan2(y, x) * 180) / Math.PI + 450) % 360);
    const radius = Math.min(1, Math.hypot(x, y) / (rect.width / 2));
    onChange(`${hue} ${(radius * accentMaxChroma).toFixed(3)}`);
  };

  const onKeyDown = (e: KeyboardEvent) => {
    let hue = selected?.hue ?? 200;
    let chroma = selected?.chroma ?? 0.13;
    if (e.key === "ArrowLeft") hue = (hue + 355) % 360;
    else if (e.key === "ArrowRight") hue = (hue + 5) % 360;
    else if (e.key === "ArrowUp")
      chroma = Math.min(accentMaxChroma, chroma + 0.01);
    else if (e.key === "ArrowDown") chroma = Math.max(0, chroma - 0.01);
    else return;
    e.preventDefault();
    onChange(`${Math.round(hue)} ${chroma.toFixed(3)}`);
  };

  const angle = (((selected?.hue ?? 0) - 90) * Math.PI) / 180;
  const radius = selected ? (selected.chroma / accentMaxChroma) * 50 : 0;
  return (
    <div
      className="accent-wheel"
      role="slider"
      tabIndex={0}
      aria-label={t(
        "Accent color — left/right arrows change the hue, up/down how colorful",
      )}
      aria-valuemin={0}
      aria-valuemax={359}
      aria-valuenow={selected ? Math.round(selected.hue) : 0}
      aria-valuetext={
        selected
          ? t("hue {hue}°, {pct}% colorful", {
              hue: String(Math.round(selected.hue)),
              pct: String(
                Math.round((selected.chroma / accentMaxChroma) * 100),
              ),
            })
          : t("theme default")
      }
      style={{ background: accentWheelFace }}
      onPointerDown={(e) => {
        (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
        dragging.current = true;
        pick(e);
      }}
      onPointerMove={(e) => dragging.current && pick(e)}
      onPointerUp={() => (dragging.current = false)}
      onPointerCancel={() => (dragging.current = false)}
      onKeyDown={onKeyDown}
    >
      {selected && (
        <span
          className="accent-wheel-thumb"
          style={{
            left: `${50 + radius * Math.cos(angle)}%`,
            top: `${50 + radius * Math.sin(angle)}%`,
            // The resulting pair rings the picked spot: light/dark split like
            // the preset dots, with the wheel showing through the center.
            background: `linear-gradient(135deg, ${accentPair(value)!.light} 50%, ${accentPair(value)!.dark} 50%)`,
          }}
        ></span>
      )}
    </div>
  );
}
