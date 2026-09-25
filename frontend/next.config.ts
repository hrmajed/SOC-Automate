import type { NextConfig } from "next";

const apiUrl = process.env.SOC_API_URL ?? "http://127.0.0.1:8765";

const nextConfig: NextConfig = {
  devIndicators: false,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiUrl}/api/:path*` }];
  },
};

export default nextConfig;
