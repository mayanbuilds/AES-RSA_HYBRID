import { defineConfig } from 'vite';

export default defineConfig({
  // Vercel deploys to root, so base is /
  base: '/',
  server: {
    port: 3000,
    host: '0.0.0.0',
    hmr: process.env.DISABLE_HMR !== 'true',
    watch: process.env.DISABLE_HMR === 'true' ? null : {},
  },
  build: {
    // Ensure script.js is treated as a module entry and included in the build
    rollupOptions: {
      input: 'index.html',
    },
  },
});
