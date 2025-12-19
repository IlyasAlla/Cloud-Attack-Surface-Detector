import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "../components/Sidebar";

export const metadata: Metadata = {
  title: "Cloud Attack Surface Command Center",
  description: "Red Team Orchestration Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <div style={{ display: "flex" }}>
          <Sidebar />
          <main style={{ flex: 1, marginLeft: "280px", padding: "2rem" }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
