import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// The compose stack publishes the audit app on 8899. `VITE_API_TARGET` points the dev
// server at whatever is actually running locally, so a dev session does not have to be on
// the same port the deployment uses.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const target = env.VITE_API_TARGET || 'http://127.0.0.1:8899';

  return {
    plugins: [react(), tailwindcss()],
    server: { proxy: { '/api': target } },
    build: { outDir: 'dist', sourcemap: false },
  };
});
