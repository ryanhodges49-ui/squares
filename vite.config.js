import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'squares.html'),
        onboarding: resolve(__dirname, 'onboarding-demo.html'),
      }
    }
  }
})
