/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The app talks to the API on its own origin (VITE_API_BASE_URL), the same way it will in production.
// The API's CORS allows APP_URL (http://localhost:5173) with credentials, and its refresh cookie is
// HttpOnly + SameSite=Strict on path /auth, so it is sent only to the API's own /auth endpoints.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true },
  preview: { port: 5173, strictPort: true },
  build: { sourcemap: false },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
