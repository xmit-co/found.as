import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import basicSsl from "@vitejs/plugin-basic-ssl"; // https://vitejs.dev/config/

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [preact(), basicSsl()],
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
    },
  },
});
