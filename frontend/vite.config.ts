/// <reference types="vitest" />
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import fs from "fs"
import path from "path"
import { fileURLToPath } from "url"

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const proxyTarget = process.env.SEAGULL_API_PROXY_TARGET || "http://seagull-backend:8000"

const FLAG_ROUTE = "/flags/3x2/"
const FLAG_FILE = /^[A-Z]{2}\.svg$/
const flagSourceDir = path.resolve(__dirname, "node_modules/country-flag-icons/3x2")

function countryFlagAssets(): Plugin {
  return {
    name: "seagull-country-flag-assets",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = (req.url ?? "").split("?")[0]
        if (!url.startsWith(FLAG_ROUTE)) return next()

        const name = path.basename(url)
        if (!FLAG_FILE.test(name)) return next()

        fs.readFile(path.join(flagSourceDir, name), (error, body) => {
          if (error) return next()
          res.setHeader("Content-Type", "image/svg+xml")
          res.setHeader("Cache-Control", "public, max-age=3600")
          res.end(body)
        })
      })
    },
    generateBundle() {
      const names = fs.readdirSync(flagSourceDir).filter((name) => FLAG_FILE.test(name))
      if (names.length === 0) {
        this.error(
          `No country flags found in ${flagSourceDir}. ` +
            "Install dependencies (npm ci) before building the frontend.",
        )
      }
      for (const name of names) {
        this.emitFile({
          type: "asset",
          fileName: `flags/3x2/${name}`,
          source: fs.readFileSync(path.join(flagSourceDir, name)),
        })
      }
    },
  }
}

export default defineConfig({
  plugins: [react(), countryFlagAssets()],
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
