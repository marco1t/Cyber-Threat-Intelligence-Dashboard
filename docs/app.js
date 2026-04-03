// app.js — CTI Dashboard v2.0

document.addEventListener('DOMContentLoaded', () => {

    // ─── DOM refs ────────────────────────────────────────────────
    const grid        = document.getElementById('alerts-grid');
    const filterBtns  = document.querySelectorAll('.filter-btn');
    const updateText  = document.getElementById('last-updated-text');
    const kpiTotal    = document.querySelector('#kpi-total .kpi-value');
    const kpiCritical = document.querySelector('#kpi-critical .kpi-value');
    const kpiMatch    = document.querySelector('#kpi-match .kpi-value');
    const datePicker  = document.getElementById('date-picker');
    const alertCountLabel = document.getElementById('alert-count-label');
    const navItems    = document.querySelectorAll('.nav-item[data-view]');
    const mobileNavItems = document.querySelectorAll('.mobile-nav-item[data-view]');
    const views       = document.querySelectorAll('.view');
    const sidebarFilters = document.getElementById('sidebar-filters');
    const sidebarDate    = document.getElementById('sidebar-date');
    const sidebar        = document.getElementById('sidebar');
    const overlay        = document.getElementById('sidebar-overlay');
    const hamburgerBtn   = document.getElementById('hamburger-btn');

    let allAlerts = [];
    let trendChartInstance  = null;
    let sourceChartInstance = null;
    let severityChartInstance = null;
    let indexData = [];

    // ─── MOBILE SIDEBAR TOGGLE ───────────────────────────────────

    function openSidebar() {
        sidebar.classList.add('open');
        overlay.classList.add('visible');
        hamburgerBtn.classList.add('open');
        document.body.style.overflow = 'hidden';
    }

    function closeSidebar() {
        sidebar.classList.remove('open');
        overlay.classList.remove('visible');
        hamburgerBtn.classList.remove('open');
        document.body.style.overflow = '';
    }

    hamburgerBtn.addEventListener('click', () => {
        sidebar.classList.contains('open') ? closeSidebar() : openSidebar();
    });

    overlay.addEventListener('click', closeSidebar);

    // ─── NAVIGATION ──────────────────────────────────────────────

    function showView(viewName) {
        // Sync sidebar nav
        navItems.forEach(item => {
            item.classList.toggle('active', item.dataset.view === viewName);
        });
        // Sync mobile bottom nav
        mobileNavItems.forEach(item => {
            item.classList.toggle('active', item.dataset.view === viewName);
        });
        // Show/hide views
        views.forEach(v => {
            v.classList.toggle('active', v.id === `view-${viewName}`);
        });
        // Show/hide filters & date only on overview
        const isOverview = viewName === 'overview';
        if (sidebarFilters) sidebarFilters.style.display = isOverview ? '' : 'none';
        if (sidebarDate)    sidebarDate.style.display    = isOverview ? '' : 'none';

        // Scroll to top on view change
        window.scrollTo({ top: 0, behavior: 'smooth' });

        if (viewName === 'historique') renderHistorique();
        if (viewName === 'rapports')   renderRapports();
    }

    navItems.forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            showView(item.dataset.view);
            closeSidebar();
        });
    });

    mobileNavItems.forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            showView(item.dataset.view);
        });
    });

    // ─── TREND CHART (overview) ──────────────────────────────────

    async function fetchIndexAndInitChart() {
        try {
            const response = await fetch('data/index.json', { cache: 'no-store' });
            if (!response.ok) return;
            indexData = await response.json();

            const recentData = indexData.slice(-30);
            const labels      = recentData.map(item => item.date);
            const criticalData = recentData.map(item => item.critical_cves);

            const ctx = document.getElementById('trendChart').getContext('2d');
            if (trendChartInstance) trendChartInstance.destroy();

            trendChartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Vulnérabilités Critiques',
                        data: criticalData,
                        borderColor: 'rgba(168, 85, 247, 1)',
                        backgroundColor: 'rgba(124, 58, 237, 0.08)',
                        pointBackgroundColor: 'rgba(168, 85, 247, 1)',
                        pointBorderColor: 'rgba(124, 58, 237, 0.5)',
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
                                color: '#64748b',
                                font: { family: 'Inter', size: 12 },
                                boxWidth: 12, boxHeight: 12
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(13, 18, 32, 0.9)',
                            borderColor: 'rgba(124, 58, 237, 0.3)',
                            borderWidth: 1,
                            titleColor: '#f1f5f9',
                            bodyColor: '#94a3b8',
                            padding: 10
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 11 } },
                            grid: { color: 'rgba(255,255,255,0.04)' }
                        },
                        y: {
                            ticks: { color: '#475569', stepSize: 1, font: { family: 'JetBrains Mono', size: 11 } },
                            grid: { color: 'rgba(255,255,255,0.04)' },
                            beginAtZero: true
                        }
                    }
                }
            });

            if (recentData.length > 0) {
                const latestDate = recentData[recentData.length - 1].date;
                datePicker.value = latestDate;
                datePicker.max   = latestDate;
            }
        } catch (error) {
            console.error("Impossible de charger l'historique :", error);
        }
    }

    // ─── ALERT DATA (overview) ───────────────────────────────────

    async function fetchThreatData(targetFile = 'data/data.json') {
        try {
            grid.innerHTML = '<div class="loader"><div class="loader-spinner"></div><span>Analyse en cours...</span></div>';
            const response = await fetch(targetFile, { cache: 'no-store' });
            if (!response.ok) throw new Error('HTTP ' + response.status);
            const data = await response.json();

            allAlerts = data.alerts || [];
            formatLastUpdated(data.last_updated);
            updateKPIs(allAlerts);
            renderAlerts(allAlerts);
        } catch (error) {
            console.error("Erreur de chargement :", error);
            grid.innerHTML = `<div class="loader" style="color:var(--red);">Erreur : impossible de charger les données. ${error.message}</div>`;
        }
    }

    function formatLastUpdated(isoString) {
        if (!isoString) return;
        const date = new Date(isoString);
        updateText.textContent = `Mise à jour : ${date.toLocaleDateString('fr-FR')} à ${date.toLocaleTimeString('fr-FR')}`;
    }

    function updateKPIs(alerts) {
        kpiTotal.textContent = alerts.length;
        const criticalCount = alerts.filter(a => {
            const sev = (a.severity || '').toUpperCase();
            return sev === 'CRITICAL' || sev === 'HIGH';
        }).length;
        kpiCritical.textContent = criticalCount;
        kpiMatch.textContent = alerts.filter(a => a.match === true).length;
    }

    function renderAlerts(alerts) {
        grid.innerHTML = '';
        if (alertCountLabel) alertCountLabel.textContent = `${alerts.length} alerte${alerts.length !== 1 ? 's' : ''}`;

        if (alerts.length === 0) {
            grid.innerHTML = '<div class="loader"><span>Aucune menace détectée.</span></div>';
            return;
        }

        alerts.forEach((alert, i) => {
            const sevClass    = getSeverityClass(alert.severity);
            const formattedDate = new Date(alert.date).toLocaleDateString('fr-FR', {
                month: 'short', day: 'numeric', year: 'numeric'
            });
            const matchBadge = alert.match
                ? '<span class="match-badge">🎯 Cible potentielle</span>'
                : '';

            const cardHTML = `
                <div class="alert-card ${sevClass}" style="animation-delay:${i * 0.03}s">
                    <div class="alert-header">
                        <span class="alert-source">${alert.source}</span>
                        <span class="alert-type">${alert.type}</span>
                    </div>
                    <div class="alert-title">
                        ${alert.title}
                        ${matchBadge}
                    </div>
                    <div class="alert-footer">
                        <span class="alert-date">${formattedDate}</span>
                        <a href="${alert.link}" target="_blank" rel="noopener noreferrer" class="alert-link">Voir détails</a>
                    </div>
                </div>
            `;
            grid.insertAdjacentHTML('beforeend', cardHTML);
        });
    }

    function getSeverityClass(severity) {
        const sev = (severity || '').toUpperCase();
        if (sev === 'CRITICAL' || sev === 'HIGH') return 'critical';
        if (sev === 'MEDIUM'   || sev === 'MODERATE') return 'high';
        return 'info';
    }

    // ─── FILTERS ─────────────────────────────────────────────────

    filterBtns.forEach(btn => {
        btn.addEventListener('click', e => {
            filterBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            const f = e.target.dataset.filter;
            let filtered = allAlerts;
            if (f === 'critical') {
                filtered = allAlerts.filter(a => {
                    const sev = (a.severity || '').toUpperCase();
                    return sev === 'CRITICAL' || sev === 'HIGH';
                });
            } else if (f === 'servers') {
                filtered = allAlerts.filter(a => a.match === true);
            }
            renderAlerts(filtered);
        });
    });

    datePicker.addEventListener('change', e => {
        if (e.target.value) fetchThreatData(`data/${e.target.value}.json`);
    });

    // ─── HISTORIQUE VIEW ─────────────────────────────────────────

    function renderHistorique() {
        const tbody = document.getElementById('history-tbody');
        const histCount = document.getElementById('hist-count');
        const histSessions = document.getElementById('hist-stat-sessions');
        const histTotal    = document.getElementById('hist-stat-total');
        const histCritical = document.getElementById('hist-stat-critical');

        if (!indexData || indexData.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="table-empty">Aucune donnée historique disponible.</td></tr>';
            return;
        }

        const sorted = [...indexData].sort((a, b) => b.date.localeCompare(a.date));
        histCount.textContent = `${sorted.length} entrée${sorted.length !== 1 ? 's' : ''}`;

        // Stats globales
        const totalAll    = sorted.reduce((s, d) => s + (d.total_cves || 0), 0);
        const criticalAll = sorted.reduce((s, d) => s + (d.critical_cves || 0), 0);
        histSessions.textContent = sorted.length;
        histTotal.textContent    = totalAll;
        histCritical.textContent = criticalAll;

        // Table
        tbody.innerHTML = sorted.map(entry => {
            const rate = entry.total_cves > 0
                ? Math.round((entry.critical_cves / entry.total_cves) * 100)
                : 0;
            const rateClass = rate > 20 ? 'rate--high' : rate > 0 ? 'rate--med' : 'rate--low';
            const dateFmt = new Date(entry.date).toLocaleDateString('fr-FR', {
                weekday: 'short', year: 'numeric', month: 'long', day: 'numeric'
            });

            return `
                <tr class="history-row" data-date="${entry.date}" data-file="${entry.file}">
                    <td>
                        <span class="mono date-cell">${dateFmt}</span>
                    </td>
                    <td><span class="num-cell">${entry.total_cves}</span></td>
                    <td>
                        <span class="num-cell ${entry.critical_cves > 0 ? 'num--red' : ''}">${entry.critical_cves}</span>
                    </td>
                    <td>
                        <span class="rate-badge ${rateClass}">${rate}%</span>
                    </td>
                    <td>
                        <button class="btn-load-session" data-date="${entry.date}" data-file="${entry.file}">
                            Charger →
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        // Click on row or button → go to overview with that date's data
        tbody.querySelectorAll('.btn-load-session').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                const date = btn.dataset.date;
                datePicker.value = date;
                fetchThreatData(`data/${date}.json`);
                showView('overview');
            });
        });
    }

    // ─── RAPPORTS VIEW ───────────────────────────────────────────

    function renderRapports() {
        const reportDateLabel = document.getElementById('report-date-label');
        const statGrid        = document.getElementById('stat-grid');

        if (allAlerts.length === 0) {
            statGrid.innerHTML = '<div class="loader"><span>Aucune donnée chargée. Revenez à la vue d\'ensemble d\'abord.</span></div>';
            return;
        }

        // Date label
        reportDateLabel.textContent = datePicker.value || 'Aujourd\'hui';

        // ─ Source breakdown
        const sourceCounts = {};
        allAlerts.forEach(a => {
            sourceCounts[a.source] = (sourceCounts[a.source] || 0) + 1;
        });
        const sourceLabels = Object.keys(sourceCounts);
        const sourceVals   = Object.values(sourceCounts);
        const sourceColors = ['rgba(124,58,237,0.8)','rgba(6,182,212,0.8)','rgba(16,185,129,0.8)','rgba(245,158,11,0.8)','rgba(239,68,68,0.8)'];

        const ctxSource = document.getElementById('sourceChart').getContext('2d');
        if (sourceChartInstance) sourceChartInstance.destroy();
        sourceChartInstance = new Chart(ctxSource, {
            type: 'bar',
            data: {
                labels: sourceLabels,
                datasets: [{
                    label: 'Alertes',
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
                        backgroundColor: 'rgba(13,18,32,0.9)',
                        borderColor: 'rgba(124,58,237,0.3)',
                        borderWidth: 1,
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        padding: 10
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 11 } },
                        grid: { display: false }
                    },
                    y: {
                        ticks: { color: '#475569', stepSize: 1, font: { family: 'JetBrains Mono', size: 11 } },
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        beginAtZero: true
                    }
                }
            }
        });

        // ─ Severity breakdown
        const sevLabels = ['Critique / Haute', 'Moyenne', 'Info'];
        const sevVals = [
            allAlerts.filter(a => { const s=(a.severity||'').toUpperCase(); return s==='CRITICAL'||s==='HIGH'; }).length,
            allAlerts.filter(a => { const s=(a.severity||'').toUpperCase(); return s==='MEDIUM'||s==='MODERATE'; }).length,
            allAlerts.filter(a => { const s=(a.severity||'').toUpperCase(); return s!=='CRITICAL'&&s!=='HIGH'&&s!=='MEDIUM'&&s!=='MODERATE'; }).length
        ];
        const sevColors = ['rgba(239,68,68,0.8)', 'rgba(245,158,11,0.8)', 'rgba(6,182,212,0.8)'];

        const ctxSev = document.getElementById('severityChart').getContext('2d');
        if (severityChartInstance) severityChartInstance.destroy();
        severityChartInstance = new Chart(ctxSev, {
            type: 'doughnut',
            data: {
                labels: sevLabels,
                datasets: [{
                    data: sevVals,
                    backgroundColor: sevColors,
                    borderColor: 'rgba(13,18,32,0.8)',
                    borderWidth: 3,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#64748b', font: { family: 'Inter', size: 12 }, padding: 16, boxWidth: 12, boxHeight: 12 }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(13,18,32,0.9)',
                        borderColor: 'rgba(124,58,237,0.3)',
                        borderWidth: 1,
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        padding: 10
                    }
                }
            }
        });

        // ─ Stat tiles
        const matchCount = allAlerts.filter(a => a.match).length;
        const rssCount   = allAlerts.filter(a => a.type === 'Article RSS').length;
        const cveCount   = allAlerts.filter(a => a.type !== 'Article RSS').length;
        const matchRate  = allAlerts.length > 0 ? Math.round((matchCount / allAlerts.length) * 100) : 0;

        const stats = [
            { label: 'Total alertes',       value: allAlerts.length,    color: '' },
            { label: 'Articles RSS',        value: rssCount,            color: '' },
            { label: 'CVEs NIST',           value: cveCount,            color: '' },
            { label: 'Cibles potentielles', value: matchCount,          color: 'stat--purple' },
            { label: 'Taux MATCH',          value: matchRate + '%',     color: 'stat--purple' },
            { label: 'Sources actives',     value: Object.keys(sourceCounts).length, color: '' }
        ];

        statGrid.innerHTML = stats.map(s => `
            <div class="stat-tile ${s.color}">
                <p class="stat-label">${s.label}</p>
                <p class="stat-value">${s.value}</p>
            </div>
        `).join('');
    }

    // ─── INIT ─────────────────────────────────────────────────────
    fetchIndexAndInitChart().then(() => fetchThreatData());
});
