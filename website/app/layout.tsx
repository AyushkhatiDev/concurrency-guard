import type { Metadata } from "next";
import { GeistMono, GeistSans } from "geist/font";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000"),
  title: "cguard — Make race conditions visible",
  description: "Find, reproduce, and patch Python race conditions without sending your code anywhere.",
  openGraph: {
    title: "cguard — Make race conditions visible",
    description: "Find, reproduce, and patch Python race conditions without sending your code anywhere.",
    images: ["/opengraph-image"],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body className={`${GeistSans.variable} ${GeistMono.variable}`}>{children}</body></html>;
}
