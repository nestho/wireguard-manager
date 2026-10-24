import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // A separate entry point ensures the production artifact does not bundle
  // the public demo dashboard or its synthetic fixture data.
  build: {
    outDir: "dist-production",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: { input: "index.production.html" },
  },
});
