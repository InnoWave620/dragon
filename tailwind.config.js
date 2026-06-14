/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class', // support toggling dark mode via class
  theme: {
    extend: {
      colors: {
        // Sleek, premium cybersecurity theme colors
        dark: {
          bg: '#0a0b0d',         // Deep obsidian background
          surface: '#12141c',    // Elevated slate/gray surface
          border: '#1f2430',     // Subtle dark border
          card: '#151821'        // Dark card background
        },
        cyber: {
          cyan: '#00f0ff',       // Tech cyan highlight
          emerald: '#10b981',    // Success green
          rose: '#f43f5e',       // Critical alert red
          amber: '#f59e0b',      // Warning orange
          blue: '#3b82f6',       // Info/Neutral blue
          purple: '#8b5cf6'      // High threat purple
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Fira Code', 'Courier New', 'monospace']
      },
      boxShadow: {
        'glow-cyan': '0 0 10px rgba(0, 240, 255, 0.15)',
        'glow-rose': '0 0 10px rgba(244, 63, 94, 0.15)',
        'glow-emerald': '0 0 10px rgba(16, 185, 129, 0.15)',
      },
      animation: {
        'pulse-subtle': 'pulseSubtle 2s infinite ease-in-out',
        'shimmer': 'shimmer 1.5s infinite linear',
      },
      keyframes: {
        pulseSubtle: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.6' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        }
      }
    },
  },
  plugins: [],
}
