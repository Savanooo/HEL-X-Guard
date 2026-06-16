import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "HELİX-Guard — Firmware Security",
  description: "Static firmware binary security analysis platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
