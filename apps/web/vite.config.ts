import { defineConfig } from "vite";
export default defineConfig({
  root: "client",
  build: { outDir: "../dist/client", emptyOutDir: true, target: "es2022" },
  server: { port: 5173, proxy: { "/auth": "http://localhost:7000", "/config": "http://localhost:7000" } },
});
