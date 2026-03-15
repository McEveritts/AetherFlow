import type { NextConfig } from "next";

const isStaticExport = process.env.NEXT_STATIC_EXPORT === "1";

const nextConfig: NextConfig = {
  output: isStaticExport ? "export" : undefined,
  images: isStaticExport ? { unoptimized: true } : undefined,
  async rewrites() {
    if (isStaticExport) {
      return [];
    }

    return [
      {
        source: '/api/:path*',
        destination: process.env.API_PROXY_TARGET || 'http://127.0.0.1:8080/api/:path*',
      },
    ];
  },
};

export default nextConfig;
