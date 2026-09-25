import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { TooltipProvider } from "@/components/ui/tooltip";
import "./globals.css";

export const metadata: Metadata = {
  title: "SOC Copilot · Alert triage",
  description: "Local, context-aware alert triage with a guarded AI investigation agent.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`dark ${GeistSans.variable} ${GeistMono.variable}`}>
      <body className="antialiased">
        <TooltipProvider delayDuration={150}>{children}</TooltipProvider>
      </body>
    </html>
  );
}
