import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
    // Base path for GitHub Pages deployment
    base: './',

    server: {
        port: 3000,
        // Proxy /data and /history.json to ../docs during dev
        proxy: {},
        // Serve ../docs/data and ../docs/history.json as static files
        fs: {
            allow: ['..'],
        },
    },

    // Copy data files to build output for production
    build: {
        outDir: '../docs_new',
        emptyOutDir: true,
        rollupOptions: {
            input: resolve(__dirname, 'index.html'),
        },
    },

    // public/data is a junction to ../docs/data for dev mode
    publicDir: 'public',
});
