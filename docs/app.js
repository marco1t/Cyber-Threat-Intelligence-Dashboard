document.addEventListener("DOMContentLoaded", () => {
    const cyberGrid = document.getElementById("cyber-alerts-grid");
    const aiGrid = document.getElementById("ai-alerts-grid");
    const filterBtns = document.querySelectorAll(".filter-btn");
    const updateText = document.getElementById("last-updated-text");
    const kpiCyber = document.querySelector("#kpi-total .kpi-value");
    const kpiAi = document.querySelector("#kpi-critical .kpi-value");
    const kpiPriority = document.querySelector("#kpi-match .kpi-value");
    const datePicker = document.getElementById("date-picker");
    const cyberCountLabel = document.getElementById("cyber-alert-count-label");
    const aiCountLabel = document.getElementById("ai-alert-count-label");
    const navItems = document.querySelectorAll(".nav-item[data-view]");
    const mobileNavItems = document.querySelectorAll(".mobile-nav-item[data-view]");
    const views = document.querySelectorAll(".view");
    const sidebarFilters = document.getElementById("sidebar-filters");
    const sidebarDate = document.getElementById("sidebar-date");
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("sidebar-overlay");
    const hamburgerBtn = document.getElementById("hamburger-btn");

    let allAlerts = [];
    let streamAlerts = { cyber: [], ai: [] };
    let currentFilter = "all";
    let trendChartInstance = null;
    let sourceChartInstance = null;
    let severityChartInstance = null;
    let indexData = [];

    function escapeHtml(text) {
        return String(text || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function openSidebar() {
        sidebar.classList.add("open");
        overlay.classList.add("visible");
        hamburgerBtn.classList.add("open");
        document.body.style.overflow = "hidden";
    }

    function closeSidebar() {
        sidebar.classList.remove("open");
        overlay.classList.remove("visible");
        hamburgerBtn.classList.remove("open");
        document.body.style.overflow = "";
    }

    hamburgerBtn.addEventListener("click", () => {
        sidebar.classList.contains("open") ? closeSidebar() : openSidebar();
    });

    overlay.addEventListener("click", closeSidebar);

    function showView(viewName) {
        navItems.forEach(item => {
            item.classList.toggle("active", item.dataset.view === viewName);
        });
        mobileNavItems.forEach(item => {
            item.classList.toggle("active", item.dataset.view === viewName);
        });
        views.forEach(view => {
            view.classList.toggle("active", view.id === `view-${viewName}`);
        });

        const isOverview = viewName === "overview";
        if (sidebarFilters) sidebarFilters.style.display = isOverview ? "" : "none";
        if (sidebarDate) sidebarDate.style.display = isOverview ? "" : "none";

        window.scrollTo({ top: 0, behavior: "smooth" });

        if (viewName === "historique") renderHistorique();
        if (viewName === "rapports") renderRapports();
    }

    navItems.forEach(item => {
        item.addEventListener("click", event => {
            event.preventDefault();
            showView(item.dataset.view);
            closeSidebar();
        });
    });

    mobileNavItems.forEach(item => {
        item.addEventListener("click", event => {
            event.preventDefault();
            showView(item.dataset.view);
        });
    });

    function deriveStreams(data) {
        if (data.streams && data.streams.cyber && data.streams.ai) {
            return data.streams;
        }

        const derived = { cyber: [], ai: [] };
        (data.alerts || []).forEach(alert => {
            if ((alert.stream || "cyber") === "ai") {
                derived.ai.push(alert);
            } else {
                derived.cyber.push(alert);
            }
        });
        return derived;
    }

    async function fetchIndexAndInitChart() {
        try {
            const response = await fetch("data/index.json", { cache: "no-store" });
            if (!response.ok) return;
            indexData = await response.json();

            const recentData = indexData.slice(-30);
            const labels = recentData.map(item => item.date);
            const priorityData = recentData.map(item => item.priority_alerts ?? item.critical_cves ?? 0);

            const ctx = document.getElementById("trendChart").getContext("2d");
            if (trendChartInstance) trendChartInstance.destroy();

            trendChartInstance = new Chart(ctx, {
                type: "line",
                data: {
                    labels,
                    datasets: [{
                        label: "Alertes prioritaires",
                        data: priorityData,
                        borderColor: "rgba(168, 85, 247, 1)",
                        backgroundColor: "rgba(124, 58, 237, 0.08)",
                        pointBackgroundColor: "rgba(168, 85, 247, 1)",
                        pointBorderColor: "rgba(124, 58, 237, 0.5)",
                        pointRadius: 4,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: "#64748b",
                                font: { family: "Inter", size: 12 },
                                boxWidth: 12,
                                boxHeight: 12
                            }
                        },
                        tooltip: {
                            backgroundColor: "rgba(13, 18, 32, 0.9)",
                            borderColor: "rgba(124, 58, 237, 0.3)",
                            borderWidth: 1,
                            titleColor: "#f1f5f9",
                            bodyColor: "#94a3b8",
                            padding: 10
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: "#475569", font: { family: "JetBrains Mono", size: 11 } },
                            grid: { color: "rgba(255,255,255,0.04)" }
                        },
                        y: {
                            ticks: { color: "#475569", stepSize: 1, font: { family: "JetBrains Mono", size: 11 } },
                            grid: { color: "rgba(255,255,255,0.04)" },
                            beginAtZero: true
                        }
                    }
                }
            });

            if (recentData.length > 0) {
                const latestDate = recentData[recentData.length - 1].date;
                datePicker.value = latestDate;
                datePicker.max = latestDate;
            }
        } catch (error) {
            console.error("Impossible de charger l'historique :", error);
        }
    }

    async function fetchThreatData(targetFile = "data/data.json") {
        try {
            cyberGrid.innerHTML = '<div class="loader"><div class="loader-spinner"></div><span>Analyse cyber en cours...</span></div>';
            aiGrid.innerHTML = '<div class="loader"><div class="loader-spinner"></div><span>Analyse IA en cours...</span></div>';

            const response = await fetch(targetFile, { cache: "no-store" });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const data = await response.json();

            streamAlerts = deriveStreams(data);
            allAlerts = [...streamAlerts.cyber, ...streamAlerts.ai];

            formatLastUpdated(data.last_updated);
            updateKPIs(data.summary || {});
            applyOverviewFilter(currentFilter);
        } catch (error) {
            console.error("Erreur de chargement :", error);
            cyberGrid.innerHTML = `<div class="loader" style="color:var(--red);">Erreur : ${escapeHtml(error.message)}</div>`;
            aiGrid.innerHTML = `<div class="loader" style="color:var(--red);">Erreur : ${escapeHtml(error.message)}</div>`;
        }
    }

    function formatLastUpdated(isoString) {
        if (!isoString) return;
        const date = new Date(isoString);
        updateText.textContent = `Mise à jour : ${date.toLocaleDateString("fr-FR")} à ${date.toLocaleTimeString("fr-FR")}`;
    }

    function updateKPIs(summary) {
        kpiCyber.textContent = summary.cyber_alerts ?? streamAlerts.cyber.length;
        kpiAi.textContent = summary.ai_alerts ?? streamAlerts.ai.length;
        kpiPriority.textContent = summary.priority_alerts ?? allAlerts.filter(alert => alert.match).length;
    }

    function getSeverityClass(severity) {
        const value = (severity || "").toUpperCase();
        if (value === "CRITICAL" || value === "HIGH") return "critical";
        if (value === "MEDIUM" || value === "MODERATE") return "high";
        return "info";
    }

    function renderAlertCards(alerts, targetGrid, labelNode, emptyText) {
        targetGrid.innerHTML = "";
        if (labelNode) {
            labelNode.textContent = `${alerts.length} alerte${alerts.length !== 1 ? "s" : ""}`;
        }

        if (alerts.length === 0) {
            targetGrid.innerHTML = `<div class="loader"><span>${escapeHtml(emptyText)}</span></div>`;
            return;
        }

        alerts.forEach((alert, index) => {
            const sevClass = getSeverityClass(alert.severity);
            const formattedDate = new Date(alert.date).toLocaleDateString("fr-FR", {
                month: "short",
                day: "numeric",
                year: "numeric"
            });
            const matchBadge = alert.match
                ? '<span class="match-badge">Prioritaire</span>'
                : "";
            const tags = Array.isArray(alert.tags) && alert.tags.length > 0
                ? `<div class="alert-tags">${alert.tags.map(tag => `<span class="alert-tag">${escapeHtml(tag)}</span>`).join("")}</div>`
                : "";
            const summary = alert.summary
                ? `<p class="alert-summary">${escapeHtml(alert.summary)}</p>`
                : "";
            const reason = alert.reason
                ? `<p class="alert-reason">${escapeHtml(alert.reason)}</p>`
                : "";

            const cardHtml = `
                <div class="alert-card ${sevClass}" style="animation-delay:${index * 0.03}s">
                    <div class="alert-header">
                        <span class="alert-source">${escapeHtml(alert.source)}</span>
                        <span class="alert-type">${escapeHtml(alert.type || "Veille")}</span>
                    </div>
                    <div class="alert-title">
                        ${escapeHtml(alert.title)}
                        ${matchBadge}
                    </div>
                    ${summary}
                    ${reason}
                    ${tags}
                    <div class="alert-footer">
                        <span class="alert-date">${formattedDate}</span>
                        <a href="${escapeHtml(alert.link)}" target="_blank" rel="noopener noreferrer" class="alert-link">Voir détails</a>
                    </div>
                </div>
            `;
            targetGrid.insertAdjacentHTML("beforeend", cardHtml);
        });
    }

    function applyOverviewFilter(filter) {
        currentFilter = filter;

        let cyberAlerts = [...streamAlerts.cyber];
        let aiAlerts = [...streamAlerts.ai];

        if (filter === "cyber") {
            aiAlerts = [];
        } else if (filter === "ai") {
            cyberAlerts = [];
        } else if (filter === "stack") {
            cyberAlerts = streamAlerts.cyber.filter(alert => alert.match === true);
            aiAlerts = streamAlerts.ai.filter(alert => alert.match === true);
        }

        renderAlertCards(cyberAlerts, cyberGrid, cyberCountLabel, "Aucune alerte cyber retenue.");
        renderAlertCards(aiAlerts, aiGrid, aiCountLabel, "Aucune alerte IA retenue.");
    }

    filterBtns.forEach(button => {
        button.addEventListener("click", event => {
            filterBtns.forEach(item => item.classList.remove("active"));
            event.currentTarget.classList.add("active");
            applyOverviewFilter(event.currentTarget.dataset.filter);
        });
    });

    datePicker.addEventListener("change", event => {
        if (event.target.value) {
            fetchThreatData(`data/${event.target.value}.json`);
        }
    });

    function renderHistorique() {
        const tbody = document.getElementById("history-tbody");
        const histCount = document.getElementById("hist-count");
        const histSessions = document.getElementById("hist-stat-sessions");
        const histTotal = document.getElementById("hist-stat-total");
        const histCritical = document.getElementById("hist-stat-critical");

        if (!indexData || indexData.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="table-empty">Aucune donnée historique disponible.</td></tr>';
            return;
        }

        const sorted = [...indexData].sort((left, right) => right.date.localeCompare(left.date));
        histCount.textContent = `${sorted.length} entrée${sorted.length !== 1 ? "s" : ""}`;

        const totalAll = sorted.reduce((sum, item) => sum + (item.total_alerts ?? item.total_cves ?? 0), 0);
        const priorityAll = sorted.reduce((sum, item) => sum + (item.priority_alerts ?? item.critical_cves ?? 0), 0);
        histSessions.textContent = sorted.length;
        histTotal.textContent = totalAll;
        histCritical.textContent = priorityAll;

        tbody.innerHTML = sorted.map(entry => {
            const total = entry.total_alerts ?? entry.total_cves ?? 0;
            const cyber = entry.cyber_alerts ?? 0;
            const ai = entry.ai_alerts ?? 0;
            const priority = entry.priority_alerts ?? entry.critical_cves ?? 0;
            const dateFormatted = new Date(entry.date).toLocaleDateString("fr-FR", {
                weekday: "short",
                year: "numeric",
                month: "long",
                day: "numeric"
            });

            return `
                <tr class="history-row" data-date="${entry.date}" data-file="${entry.file}">
                    <td><span class="mono date-cell">${dateFormatted}</span></td>
                    <td><span class="num-cell">${total}</span></td>
                    <td><span class="num-cell">${cyber}</span></td>
                    <td><span class="num-cell">${ai}</span></td>
                    <td><span class="num-cell ${priority > 0 ? "num--red" : ""}">${priority}</span></td>
                    <td><button class="btn-load-session" data-date="${entry.date}" data-file="${entry.file}">Charger →</button></td>
                </tr>
            `;
        }).join("");

        tbody.querySelectorAll(".btn-load-session").forEach(button => {
            button.addEventListener("click", event => {
                event.stopPropagation();
                const date = button.dataset.date;
                datePicker.value = date;
                fetchThreatData(`data/${date}.json`);
                showView("overview");
            });
        });
    }

    function renderRapports() {
        const reportDateLabel = document.getElementById("report-date-label");
        const statGrid = document.getElementById("stat-grid");

        if (allAlerts.length === 0) {
            statGrid.innerHTML = "<div class=\"loader\"><span>Aucune donnée chargée.</span></div>";
            return;
        }

        reportDateLabel.textContent = datePicker.value || "Aujourd'hui";

        const sourceCounts = {};
        allAlerts.forEach(alert => {
            sourceCounts[alert.source] = (sourceCounts[alert.source] || 0) + 1;
        });

        const sourceLabels = Object.keys(sourceCounts);
        const sourceVals = Object.values(sourceCounts);
        const sourceColors = [
            "rgba(124,58,237,0.8)",
            "rgba(6,182,212,0.8)",
            "rgba(16,185,129,0.8)",
            "rgba(245,158,11,0.8)",
            "rgba(239,68,68,0.8)",
            "rgba(59,130,246,0.8)"
        ];

        const sourceCtx = document.getElementById("sourceChart").getContext("2d");
        if (sourceChartInstance) sourceChartInstance.destroy();
        sourceChartInstance = new Chart(sourceCtx, {
            type: "bar",
            data: {
                labels: sourceLabels,
                datasets: [{
                    label: "Alertes",
                    data: sourceVals,
                    backgroundColor: sourceColors.slice(0, sourceLabels.length),
                    borderRadius: 6,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "rgba(13,18,32,0.9)",
                        borderColor: "rgba(124,58,237,0.3)",
                        borderWidth: 1,
                        titleColor: "#f1f5f9",
                        bodyColor: "#94a3b8",
                        padding: 10
                    }
                },
                scales: {
                    x: {
                        ticks: { color: "#475569", font: { family: "JetBrains Mono", size: 11 } },
                        grid: { display: false }
                    },
                    y: {
                        ticks: { color: "#475569", stepSize: 1, font: { family: "JetBrains Mono", size: 11 } },
                        grid: { color: "rgba(255,255,255,0.04)" },
                        beginAtZero: true
                    }
                }
            }
        });

        const streamCounts = {
            Cyber: streamAlerts.cyber.length,
            IA: streamAlerts.ai.length
        };

        const streamCtx = document.getElementById("severityChart").getContext("2d");
        if (severityChartInstance) severityChartInstance.destroy();
        severityChartInstance = new Chart(streamCtx, {
            type: "doughnut",
            data: {
                labels: Object.keys(streamCounts),
                datasets: [{
                    data: Object.values(streamCounts),
                    backgroundColor: ["rgba(6,182,212,0.8)", "rgba(124,58,237,0.8)"],
                    borderColor: "rgba(13,18,32,0.8)",
                    borderWidth: 3,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "65%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: "#64748b",
                            font: { family: "Inter", size: 12 },
                            padding: 16,
                            boxWidth: 12,
                            boxHeight: 12
                        }
                    },
                    tooltip: {
                        backgroundColor: "rgba(13,18,32,0.9)",
                        borderColor: "rgba(124,58,237,0.3)",
                        borderWidth: 1,
                        titleColor: "#f1f5f9",
                        bodyColor: "#94a3b8",
                        padding: 10
                    }
                }
            }
        });

        const matchCount = allAlerts.filter(alert => alert.match).length;
        const stackCount = allAlerts.filter(alert => Array.isArray(alert.tags) && alert.tags.length > 0).length;

        const stats = [
            { label: "Total alertes", value: allAlerts.length, color: "" },
            { label: "Cyber", value: streamAlerts.cyber.length, color: "" },
            { label: "IA", value: streamAlerts.ai.length, color: "" },
            { label: "Prioritaires", value: matchCount, color: "stat--purple" },
            { label: "Stack perso", value: stackCount, color: "stat--purple" },
            { label: "Sources actives", value: Object.keys(sourceCounts).length, color: "" }
        ];

        statGrid.innerHTML = stats.map(stat => `
            <div class="stat-tile ${stat.color}">
                <p class="stat-label">${escapeHtml(stat.label)}</p>
                <p class="stat-value">${escapeHtml(stat.value)}</p>
            </div>
        `).join("");
    }

    fetchIndexAndInitChart().then(() => fetchThreatData());
});
