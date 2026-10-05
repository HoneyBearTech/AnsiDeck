/// <reference types="vitest/config" />
import path from "node:path";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        "@": path.resolve(import.meta.dirname, "./src"),
      },
    },
    build: {
      // Never inline assets as data: URIs: the Content-Security-Policy (frontend/docker/nginx.conf)
      // only allows fonts and images from the app's own origin.
      assetsInlineLimit: 0,
    },
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      include: ["src/**/*.test.{ts,tsx}"],
      coverage: {
        provider: "v8",
        include: ["src/**/*.{ts,tsx}"],
        // The entry point only mounts <App/>; the test helpers aren't the product.
        exclude: ["src/main.tsx", "src/vite-env.d.ts", "src/test/**", "src/**/*.test.{ts,tsx}"],
        reporter: ["text-summary", "text", "json-summary"],
        thresholds: { statements: 80 },
      },
    },
    server: {
      host: true,
      port: 5173,
      proxy: {
        "/api": {
          target: env["VITE_API_PROXY_TARGET"] || "http://localhost:8000",
          changeOrigin: true,
          ws: true,
        },
      },
    },
  };
});
