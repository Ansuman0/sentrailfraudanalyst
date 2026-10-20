import { useMemo } from "react";
import QRCode from "qrcode";

/** A QR code drawn as SVG from the module matrix (no HTML injection, no canvas, works under the strict CSP). */
export function QrCode({ value, label, size = 200 }: { value: string; label: string; size?: number }) {
  const { n, d } = useMemo(() => {
    const m = QRCode.create(value, { errorCorrectionLevel: "M" }).modules;
    const quiet = 4; // the spec's quiet zone; scanners need it
    let path = "";
    for (let r = 0; r < m.size; r++) {
      for (let c = 0; c < m.size; c++) if (m.get(r, c)) path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
    }
    return { n: m.size + quiet * 2, d: path };
  }, [value]);
  return (
    <svg className="qr" role="img" aria-label={label} viewBox={`0 0 ${n} ${n}`} width={size} height={size} shapeRendering="crispEdges">
      <rect width={n} height={n} fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  );
}
