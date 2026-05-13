import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from "path"
import { fileURLToPath } from "url"

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
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
        target: 'http://seagull-backend:8000',
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
