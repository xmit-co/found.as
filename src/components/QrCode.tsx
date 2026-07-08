import { buildQrModel } from "../qr";
import { useMemo } from "preact/hooks";

export function QrCode({
  value,
  size = 168,
}: {
  value: string;
  size?: number;
}) {
  const model = useMemo(() => {
    try {
      return buildQrModel(value);
    } catch {
      return null;
    }
  }, [value]);

  if (!model) return null;

  return (
    <svg
      className="qr-code"
      width={size}
      height={size}
      viewBox={`0 0 ${model.dim} ${model.dim}`}
      role="img"
      aria-label="QR code for this page"
      shape-rendering="crispEdges"
    >
      <rect width={model.dim} height={model.dim} fill="#ffffff" />
      {model.cells.map((cell) => (
        <rect
          key={`${cell.x}-${cell.y}`}
          x={cell.x}
          y={cell.y}
          width={1}
          height={1}
          fill="#111111"
        />
      ))}
    </svg>
  );
}
