/** @type {import('next').NextConfig} */
const isProd = process.env.NODE_ENV === 'production';

const rawBasePath =
  process.env.NEXT_PUBLIC_BASE_PATH !== undefined
    ? process.env.NEXT_PUBLIC_BASE_PATH
    : isProd
      ? '/AetherFlow'
      : '';

const normalizedBasePath = rawBasePath
  ? `/${rawBasePath.replace(/^\/+|\/+$/g, '')}`
  : '';

const nextConfig = {
  output: 'export',
  trailingSlash: true,
  basePath: normalizedBasePath,
  assetPrefix: normalizedBasePath || undefined,
  images: {
    unoptimized: true,
  },
  env: {
    NEXT_PUBLIC_BASE_PATH: normalizedBasePath,
  },
};

export default nextConfig;
