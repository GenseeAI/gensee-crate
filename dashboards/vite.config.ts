import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // Tauri loads production files from local app resources, not from a web root.
  // Relative asset URLs prevent '/assets/*' lookups that break in bundled apps.
  base: './',
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5174,
    strictPort: true,
    // No proxy needed — data access goes through Tauri IPC, not HTTP.
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
