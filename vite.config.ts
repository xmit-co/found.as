import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import basicSsl from "@vitejs/plugin-basic-ssl"; // https://vitejs.dev/config/

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [preact(), basicSsl()],
  build: {
    sourcemap: true,
  },
  server: {
    proxy: {
      "/api": {
        target: `https://be.found.as`,
        secure: false,
        changeOrigin: true,
        headers: {
          origin: `https://be.found.as`,
        },
      },
      // The IndieAuth /resolve helper lives on be.found.as; proxy it in dev.
      // GET /indieauth itself must stay local (vite serves the consent SPA).
      "/indieauth/resolve": {
        target: `https://be.found.as`,
        secure: false,
        changeOrigin: true,
        headers: {
          origin: `https://be.found.as`,
        },
      },
    },
  },
});
