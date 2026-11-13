/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: "#0b1220",
        panel: "#111b2e",
        cyan: "#33c3d8",
      },
    },
  },
  plugins: [],
};

