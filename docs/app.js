// app.js
// Logique principale du Threat Intel Dashboard

document.addEventListener('DOMContentLoaded', () => {
    // Je sélectionne mes éléments DOM principaux
    const grid = document.getElementById('alerts-grid');
    const filterBtns = document.querySelectorAll('.filter-btn');
    const updateText = document.getElementById('last-updated-text');
    
    // KPIs
    const kpiTotal = document.querySelector('#kpi-total .kpi-value');
    const kpiCritical = document.querySelector('#kpi-critical .kpi-value');
    const kpiMatch = document.querySelector('#kpi-match .kpi-value');

    // Date Picker
    const datePicker = document.getElementById('date-picker');

    // Ma variable pour stocker toutes les données récupérées
    let allAlerts = [];
    let trendChartInstance = null;

    // Je lance la récupération de l'index pour initialiser mon graphe
    async function fetchIndexAndInitChart() {
        try {
            const response = await fetch('data/index.json', { cache: "no-store" });
            if (!response.ok) return;
            const indexData = await response.json();
            
            // Je prends max 30 jours
            const recentData = indexData.slice(-30);
            const labels = recentData.map(item => item.date);
            const criticalData = recentData.map(item => item.critical_cves);
            
            const ctx = document.getElementById('trendChart').getContext('2d');
            if (trendChartInstance) {
                trendChartInstance.destroy();
            }
            
            trendChartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Vulnérabilités Critiques (30 derniers j.)',
                        data: criticalData,
                        borderColor: 'rgba(255, 69, 58, 1)',
                        backgroundColor: 'rgba(255, 69, 58, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { labels: { color: '#e5e5ea' } }
                    },
                    scales: {
                        x: { ticks: { color: '#8e8e93' }, grid: { color: '#3a3a3c' } },
                        y: { ticks: { color: '#8e8e93', stepSize: 1 }, grid: { color: '#3a3a3c' }, beginAtZero: true }
                    }
                }
            });
            
            // Si on a des dates, je définis le calendrier sur le plus récent
            if (recentData.length > 0) {
                const latestDate = recentData[recentData.length - 1].date;
                datePicker.value = latestDate;
                datePicker.max = latestDate;
            }
        } catch (error) {
            console.error("Impossible de charger l'historique :", error);
        }
    }

    // Je lance la récupération asynchrone de mes données JSON pour une date donnée ou 'data.json'
    async function fetchThreatData(targetFile = 'data/data.json') {
        try {
            grid.innerHTML = '<div class="loader">Je récupère mes données...</div>';
            // Puisque ce sera hébergé sur GitHub Pages ou en statique, je pointe vers le sous-dossier data
            const response = await fetch(targetFile, { cache: "no-store" });
            
            if (!response.ok) {
                throw new Error("HTTP erreur ! " + response.status);
            }
            
            const data = await response.json();
            
            // J'extrais mes alertes et ma date
            allAlerts = data.alerts || [];
            formatLastUpdated(data.last_updated);
            
            // Je mets à jour mon interface web avec toutes mes alertes initialement
            updateKPIs(allAlerts);
            renderAlerts(allAlerts);

        } catch (error) {
            console.error("Je n'ai pas pu charger mes données :", error);
            grid.innerHTML = `<div class="loader" style="color:var(--critical-color);">Erreur: Impossible de charger mes données. ${error.message}</div>`;
        }
    }

    // Je formate ma date récupérée
    function formatLastUpdated(isoString) {
        if (!isoString) return;
        const date = new Date(isoString);
        updateText.textContent = `Mise à jour : ${date.toLocaleDateString('fr-FR')} à ${date.toLocaleTimeString('fr-FR')}`;
    }

    // Je recalcule les KPIs dynamiquement
    function updateKPIs(alerts) {
        kpiTotal.textContent = alerts.length;
        
        const criticalCount = alerts.filter(a => {
            const sev = (a.severity || "").toUpperCase();
            return sev === "CRITICAL" || sev === "HIGH";
        }).length;
        kpiCritical.textContent = criticalCount;
        
        const matchCount = alerts.filter(a => a.match === true).length;
        kpiMatch.textContent = matchCount;
    }

    // Je rends mes cartes d'alerte en HTML
    function renderAlerts(alerts) {
        grid.innerHTML = '';
        
        if (alerts.length === 0) {
            grid.innerHTML = '<div class="loader">Aucune menace détectée.</div>';
            return;
        }

        alerts.forEach(alert => {
            const sevClass = getSeverityClass(alert.severity);
            const formattedDate = new Date(alert.date).toLocaleDateString('fr-FR', {
                month: 'short', day: 'numeric', year: 'numeric'
            });

            // Je gère le badge correspondant à mes serveurs cibles
            const matchBadge = alert.match ? '<span class="match-badge">🎯 Cible potentielle</span>' : '';

            const cardHTML = `
                <div class="alert-card ${sevClass}">
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

    // Je classe ma sévérité pour mon CSS
    function getSeverityClass(severity) {
        const sev = (severity || "").toUpperCase();
        if (sev === "CRITICAL" || sev === "HIGH") return "critical";
        if (sev === "MEDIUM" || sev === "MODERATE") return "high";
        return "info";
    }

    // Je gère le clic sur mes boutons filtres
    filterBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            // Je reset l'état actif
            filterBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');

            const filterType = e.target.dataset.filter;
            
            // J'applique mon filtre localement sur mon tableau allAlerts
            let filteredAlerts = [];
            if (filterType === 'all') {
                filteredAlerts = allAlerts;
            } else if (filterType === 'critical') {
                filteredAlerts = allAlerts.filter(a => {
                    const sev = (a.severity || "").toUpperCase();
                    return sev === "CRITICAL" || sev === "HIGH";
                });
            } else if (filterType === 'servers') {
                filteredAlerts = allAlerts.filter(a => a.match === true);
            }

            // Je re-rends l'UI
            renderAlerts(filteredAlerts);
        });
    });

    // Écouteur pour mon calendrier
    datePicker.addEventListener('change', (e) => {
        const selectedDate = e.target.value;
        if (selectedDate) {
            fetchThreatData(`data/${selectedDate}.json`);
        }
    });

    // Je lance ma récupération de l'index et des données par défaut
    fetchIndexAndInitChart().then(() => fetchThreatData());
});
