/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      gridTemplateColumns: {
        24: "repeat(24, minmax(0, 1fr))"
      }
    }
  },
  plugins: []
};
