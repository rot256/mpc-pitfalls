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

    const sunIcon = '<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
    const moonIcon = '<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 14.5A8 8 0 0 1 9.5 4a7 7 0 1 0 10.5 10.5z"/></svg>';

    const applyTheme = (theme) => {
        root.dataset.theme = theme;
        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            const next = theme === "dark" ? "light" : "dark";
            button.setAttribute("aria-label", `Switch to ${next} mode`);
            button.setAttribute("aria-pressed", String(theme === "dark"));
            button.innerHTML = theme === "dark" ? sunIcon : moonIcon;
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
