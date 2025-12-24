/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                // "Stealth UI" Palette
                background: '#0a0a0a',
                surface: '#1c1c1c',
                primary: '#3b82f6', // Electric Blue
                secondary: '#64748b',
                accent: '#f59e0b', // Cyber Yellow
                success: '#10b981',
                danger: '#ef4444',
            },
            fontFamily: {
                mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
                sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
            }
        },
    },
    plugins: [],
    darkMode: 'class',
}
