import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // GitHub Pages serves project sites from /<repository-name>/; keep local dev at /.
  base: process.env.GITHUB_ACTIONS === "true" ? "/wireguard-manager/" : "/",
  plugins: [react()],
});
