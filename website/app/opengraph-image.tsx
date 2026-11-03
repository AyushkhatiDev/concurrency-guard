import { ImageResponse } from "next/og";

export const alt = "cguard race-condition timeline";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return new ImageResponse(
    <div style={{ background: "#F4F1EA", color: "#12110F", width: "100%", height: "100%", display: "flex", flexDirection: "column", padding: "64px", fontFamily: "serif" }}>
      <div style={{ fontSize: 28, letterSpacing: 2, fontFamily: "monospace" }}>CGUARD / RACE TIMELINE</div>
      <div style={{ display: "flex", marginTop: 55, gap: 48, alignItems: "center" }}>
        <div style={{ fontSize: 78, lineHeight: 1 }}>Make race conditions visible.</div>
        <div style={{ minWidth: 345, display: "flex", flexDirection: "column", gap: 22, fontFamily: "monospace", fontSize: 18 }}>
          <div style={{ borderBottom: "2px solid #FF4D1C", paddingBottom: 9 }}>REQUEST A --- READ 100 --- WRITE 50</div>
          <div style={{ borderBottom: "2px solid #FF4D1C", paddingBottom: 9 }}>REQUEST B --- READ 100 --- WRITE 50</div>
          <div style={{ color: "#FF4D1C", fontWeight: 700 }}>X DOUBLE SPEND</div>
        </div>
      </div>
      <div style={{ marginTop: "auto", display: "flex", justifyContent: "space-between", fontFamily: "monospace", fontSize: 21 }}><span>FIND · REPRODUCE · PATCH</span><span style={{ color: "#1F7A4D" }}>VERIFIED LOCALLY</span></div>
    </div>,
    size,
  );
}
