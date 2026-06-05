(() => {
    const rows = [...document.querySelectorAll("#bug-tracker-rows tr")];
    const search = document.querySelector("#bug-search");
    const category = document.querySelector("#bug-category");
    const primitive = document.querySelector("#bug-primitive");
    const count = document.querySelector("#tracker-visible-count");
    const empty = document.querySelector("#tracker-empty");
    const form = document.querySelector("#tracker-controls");
    const chart = document.querySelector("#category-chart");
    const legend = document.querySelector("#category-chart-legend");
    const bugOverlay = document.querySelector("#bug-overlay");
    const bugPanel = bugOverlay.querySelector(".pitfall-overlay-panel");
    const bugPlaceholder = document.querySelector("#bug-overlay-placeholder");
    const details = [...document.querySelectorAll(".bug-detail")];
    const bugClose = [...document.querySelectorAll("[data-bug-close]")];
    const categoryOverlay = document.querySelector("#category-overlay");
    const categoryPlaceholder = document.querySelector("#category-overlay-placeholder");
    const categoryContents = [...document.querySelectorAll(".category-overlay-content")];
    const categoryClose = [...document.querySelectorAll("[data-category-close]")];
    let selectedBugId = "";

    const SMALL_WORDS_RE = /\b(And|Of|The|To)\b/g;
    const titleCase = (value) => value
        .replaceAll("-", " ")
        .replace(/\b\w/g, (letter) => letter.toUpperCase())
        .replace(SMALL_WORDS_RE, (word) => word.toLowerCase());

    const chartColors = ["#1a4a6e", "#c84d2f", "#678d58", "#8a5a99", "#b98322", "#3d7f91", "#9b4b5b"];
    const svgNS = "http://www.w3.org/2000/svg";

    const scrollToElementTop = (element) => {
        if (!element) return;

        element.scrollTop = 0;
        element.scrollTo?.(0, 0);
        requestAnimationFrame(() => { element.scrollTop = 0; });
    };

    const scrollPageTop = () => {
        const scrollingElement = document.scrollingElement || document.documentElement;
        scrollingElement.scrollTop = 0;
        document.documentElement.scrollTop = 0;
        document.body.scrollTop = 0;
        window.scrollTo?.(0, 0);
        requestAnimationFrame(() => {
            scrollingElement.scrollTop = 0;
            document.documentElement.scrollTop = 0;
            document.body.scrollTop = 0;
        });
    };

    const addOptions = (select, values, formatter = (value) => value) => {
        [...values].sort().forEach((value) => {
            const option = document.createElement("option");
            option.value = value;
            option.textContent = formatter(value);
            select.append(option);
        });
    };

    addOptions(category, new Set(rows.map((row) => row.dataset.category)), titleCase);
    addOptions(primitive, new Set(rows.flatMap((row) => row.dataset.primitives.split(" ").filter(Boolean))));

    const arcPoint = (cx, cy, radius, angle) => {
        const radians = (angle - 90) * Math.PI / 180;
        return [cx + radius * Math.cos(radians), cy + radius * Math.sin(radians)];
    };

    const appendSvg = (name, attributes) => {
        const element = document.createElementNS(svgNS, name);
        Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, value));
        chart.append(element);
        return element;
    };

    const drawChart = (visibleRows) => {
        const styles = getComputedStyle(document.documentElement);
        const chartEmpty = styles.getPropertyValue("--chart-empty").trim() || "#eef3f7";
        const chartHole = styles.getPropertyValue("--chart-hole").trim() || "#fafafa";
        const chartPrimary = styles.getPropertyValue("--accent").trim() || "#1a4a6e";
        const chartMuted = styles.getPropertyValue("--muted").trim() || "#555";
        const counts = new Map();
        visibleRows.forEach((row) => {
            counts.set(row.dataset.category, (counts.get(row.dataset.category) || 0) + 1);
        });

        const entries = [...counts.entries()].sort(([a], [b]) => titleCase(a).localeCompare(titleCase(b)));
        const total = visibleRows.length;
        chart.replaceChildren();
        legend.replaceChildren();

        if (total === 0) {
            appendSvg("circle", { cx: 90, cy: 90, r: 74, fill: chartEmpty });
            appendSvg("text", { x: 90, y: 94, "text-anchor": "middle", fill: chartMuted, "font-size": 12 }).textContent = "No bugs";
            return;
        }

        if (entries.length === 1) {
            appendSvg("circle", { cx: 90, cy: 90, r: 74, fill: chartColors[0] });
        } else {
            let startAngle = 0;
            entries.forEach(([categoryName, categoryCount], index) => {
                const endAngle = startAngle + (categoryCount / total) * 360;
                const [startX, startY] = arcPoint(90, 90, 74, startAngle);
                const [endX, endY] = arcPoint(90, 90, 74, endAngle);
                const largeArc = endAngle - startAngle > 180 ? 1 : 0;

                appendSvg("path", {
                    d: `M 90 90 L ${startX} ${startY} A 74 74 0 ${largeArc} 1 ${endX} ${endY} Z`,
                    fill: chartColors[index % chartColors.length]
                });

                startAngle = endAngle;
            });
        }

        appendSvg("circle", { cx: 90, cy: 90, r: 36, fill: chartHole });
        appendSvg("text", { x: 90, y: 86, "text-anchor": "middle", fill: chartPrimary, "font-size": 20, "font-weight": 700 }).textContent = total;
        appendSvg("text", { x: 90, y: 104, "text-anchor": "middle", fill: chartMuted, "font-size": 10 }).textContent = "bugs";

        entries.forEach(([categoryName, categoryCount], index) => {
            const item = document.createElement("li");
            item.innerHTML = `<span style="background: ${chartColors[index % chartColors.length]}"></span><button type="button" data-category-id="${categoryName}">${titleCase(categoryName)}</button><em>${categoryCount}</em>`;
            legend.append(item);
        });
    };

    const openBug = (row) => {
        rows.forEach((candidate) => {
            const selected = candidate === row;
            candidate.classList.toggle("is-selected", selected);
            candidate.querySelector(".bug-title-button").setAttribute("aria-expanded", String(selected));
        });

        details.forEach((detail) => {
            detail.hidden = detail.dataset.bugId !== row.dataset.bugId;
        });

        selectedBugId = row.dataset.bugId;
        bugPlaceholder.hidden = true;
        bugOverlay.hidden = false;
        document.body.classList.add("has-modal");
        scrollToElementTop(bugPanel);
        bugOverlay.querySelector(".pitfall-overlay-close").focus();
    };

    const clearSelection = () => {
        selectedBugId = "";
        rows.forEach((row) => {
            row.classList.remove("is-selected");
            row.querySelector(".bug-title-button").setAttribute("aria-expanded", "false");
        });
        details.forEach((detail) => detail.hidden = true);
        bugPlaceholder.hidden = false;
    };

    const closeBug = () => {
        bugOverlay.hidden = true;
        if (categoryOverlay.hidden) {
            document.body.classList.remove("has-modal");
        }
    };

    const renderVisibleRows = () => [...rows].filter((row) => !row.hidden);

    const openCategory = (categoryId) => {
        const active = categoryContents.find((content) => content.dataset.categoryId === categoryId);
        if (!active) return;

        categoryContents.forEach((content) => content.hidden = content !== active);
        categoryPlaceholder.hidden = true;
        categoryOverlay.hidden = false;
        document.body.classList.add("has-modal");
        categoryOverlay.querySelector(".pitfall-overlay-close").focus();
    };

    const closeCategory = () => {
        categoryOverlay.hidden = true;
        if (bugOverlay.hidden) {
            document.body.classList.remove("has-modal");
        }
        categoryContents.forEach((content) => content.hidden = true);
        categoryPlaceholder.hidden = false;
    };

    const applyFilters = () => {
        const query = search.value.trim().toLowerCase();
        let visible = 0;
        const visibleRows = [];

        rows.forEach((row) => {
            const matchesQuery = !query || row.dataset.search.includes(query);
            const matchesCategory = !category.value || row.dataset.category === category.value;
            const matchesPrimitive = !primitive.value || row.dataset.primitives.split(" ").includes(primitive.value);
            const show = matchesQuery && matchesCategory && matchesPrimitive;

            row.hidden = !show;
            if (show) {
                visible += 1;
                visibleRows.push(row);
            }
        });

        count.textContent = visible;
        empty.hidden = visible !== 0;
        drawChart(visibleRows);

        if (visibleRows.length === 0) {
            clearSelection();
            closeBug();
        } else if (selectedBugId && !visibleRows.some((row) => row.dataset.bugId === selectedBugId)) {
            clearSelection();
            closeBug();
        }
    };

    rows.forEach((row) => {
        const button = row.querySelector(".bug-title-button");
        button.setAttribute("aria-controls", `bug-detail-${row.dataset.bugId}`);
        button.setAttribute("aria-expanded", "false");
        row.addEventListener("click", (event) => {
            if (event.target.closest("a, [data-category-id]")) return;
            openBug(row);
        });
    });

    document.addEventListener("click", (event) => {
        if (event.target.closest("[data-tracker-top]")) {
            event.preventDefault();
            scrollPageTop();
            return;
        }

        if (event.target.closest("[data-bug-top]")) {
            event.preventDefault();
            scrollToElementTop(bugPanel);
            return;
        }

        const link = event.target.closest("[data-category-id]");
        if (!link || link.closest(".category-overlay-content")) return;

        event.preventDefault();
        event.stopPropagation();
        openCategory(link.dataset.categoryId);
    });

    bugClose.forEach((element) => element.addEventListener("click", closeBug));
    categoryClose.forEach((element) => element.addEventListener("click", closeCategory));
    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;

        if (!categoryOverlay.hidden) {
            closeCategory();
        } else if (!bugOverlay.hidden) {
            closeBug();
        }
    });

    form.addEventListener("input", applyFilters);
    form.addEventListener("submit", (event) => event.preventDefault());
    form.addEventListener("reset", () => requestAnimationFrame(applyFilters));
    window.addEventListener("themechange", () => drawChart(renderVisibleRows()));
    applyFilters();
})();
