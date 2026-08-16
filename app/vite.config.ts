import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Absolute, not './'. Nested routes like /cert/<digest> would otherwise
  // resolve relative asset URLs to /cert/assets/..., which the SPA fallback
  // answers with index.html — the module then fails on a text/html MIME type
  // and the page renders blank.
  base: '/',
})
