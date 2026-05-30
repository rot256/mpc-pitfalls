(() => {
    const isExternalHttpLink = (link) => {
        if (!link.href) return false;
        const url = new URL(link.href, window.location.href);
        return (url.protocol === "http:" || url.protocol === "https:") && url.origin !== window.location.origin;
    };

    document.addEventListener("DOMContentLoaded", () => {
        document.querySelectorAll("a[href]").forEach((link) => {
            if (!isExternalHttpLink(link)) return;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
        });
    });
})();
