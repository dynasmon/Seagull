/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from "path"
import { fileURLToPath } from "url"

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const proxyTarget = process.env.SEAGULL_API_PROXY_TARGET || "http://seagull-backend:8000"

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("@elastic/eui") && id.includes("/icon/assets/")) {
            return "eui-icons";
          }
          if (id.includes("node_modules") && (id.includes("react-globe.gl") || id.includes("three"))) {
            return "globe-vendor";
          }
          return undefined;
        },
      },
    },
  },
  test: {
    setupFiles: ["./tests/setup.ts"],
    // Vitest resolves @elastic/eui to its CommonJS build, which require()s the ESM-only
    // uuid package and throws on import. Point tests at the ESM build instead.
    alias: [
      { find: /^@elastic\/eui$/, replacement: path.resolve(__dirname, "node_modules/@elastic/eui/es/index.js") },
    ],
    server: {
      deps: {
        inline: [/@elastic\/eui/],
      },
    },
  },
  server: {
    host: true,
    port: 5173,
    watch: {
      usePolling: true,
    },
    proxy: {
      '/api': {
        target: proxyTarget,
        changeOrigin: true,
        ws: true,
        cookiePathRewrite: {
          "/auth": "/api/auth",
        },
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
