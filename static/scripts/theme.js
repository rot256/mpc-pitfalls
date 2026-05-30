(() => {
    const modeKey = "mpc-pitfalls-theme-mode";
    const root = document.documentElement;
    const media = window.matchMedia("(prefers-color-scheme: dark)");

    const systemTheme = () => media.matches ? "dark" : "light";

    const storedMode = () => {
        const saved = localStorage.getItem(modeKey);
        return saved === "dark" || saved === "light" ? saved : null;
    };

    const preferredTheme = () => storedMode() ?? systemTheme();

    const applyTheme = (theme) => {
        root.dataset.theme = theme;
        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            const next = theme === "dark" ? "light" : "dark";
            button.setAttribute("aria-label", `Switch to ${next} mode`);
            button.setAttribute("aria-pressed", String(theme === "dark"));
            button.textContent = theme === "dark" ? "☀" : "☾";
        });
        window.dispatchEvent(new CustomEvent("themechange", { detail: { theme } }));
    };

    document.addEventListener("DOMContentLoaded", () => {
        applyTheme(preferredTheme());
        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            button.addEventListener("click", () => {
                const next = root.dataset.theme === "dark" ? "light" : "dark";
                if (next === systemTheme()) {
                    localStorage.removeItem(modeKey);
                } else {
                    localStorage.setItem(modeKey, next);
                }
                applyTheme(next);
            });
        });
    });

    media.addEventListener("change", () => {
        if (!storedMode()) applyTheme(systemTheme());
    });
})();
