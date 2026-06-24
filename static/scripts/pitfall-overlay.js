(() => {
    const overlay = document.querySelector("#pitfall-overlay");
    if (!overlay) return;

    const panel = overlay.querySelector(".pitfall-overlay-panel");
    const details = [...overlay.querySelectorAll(".pitfall-overlay-detail")];
    const triggers = [...document.querySelectorAll("[data-pitfall-open]")];
    const closers = [...overlay.querySelectorAll("[data-pitfall-close]")];
    const toppers = [...overlay.querySelectorAll("[data-pitfall-top]")];
    let lastTrigger = null;

    const open = (id, trigger) => {
        const active = details.find((detail) => detail.dataset.pitfallId === id);
        if (!active) return;

        details.forEach((detail) => { detail.hidden = detail !== active; });
        lastTrigger = trigger || null;
        overlay.hidden = false;
        document.body.classList.add("has-modal");
        panel.scrollTop = 0;
        overlay.querySelector(".pitfall-overlay-close").focus();
    };

    const close = () => {
        overlay.hidden = true;
        document.body.classList.remove("has-modal");
        details.forEach((detail) => { detail.hidden = true; });
        if (lastTrigger) {
            lastTrigger.focus();
            lastTrigger = null;
        }
    };

    triggers.forEach((trigger) => {
        trigger.setAttribute("aria-controls", "pitfall-overlay");
        trigger.addEventListener("click", () => open(trigger.dataset.pitfallOpen, trigger));
    });

    closers.forEach((element) => element.addEventListener("click", close));
    toppers.forEach((element) => element.addEventListener("click", () => {
        panel.scrollTo({ top: 0, behavior: "smooth" });
    }));

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !overlay.hidden) close();
    });

    // Deep-link: open the matching pitfall if the URL carries its anchor.
    if (location.hash.length > 1) {
        open(decodeURIComponent(location.hash.slice(1)), null);
    }
})();
