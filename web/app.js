// app.js

document.addEventListener('DOMContentLoaded', () => {
    // Je sélectionne mes éléments DOM principaux
    const grid = document.getElementById('alerts-grid');
    const filterBtns = document.querySelectorAll('.filter-btn');
    const updateText = document.getElementById('last-updated-text');
    
    // KPIs
    const kpiTotal = document.querySelector('#kpi-total .kpi-value');
    const kpiCritical = document.querySelector('#kpi-critical .kpi-value');
    const kpiMatch = document.querySelector('#kpi-match .kpi-value');

    // Ma variable pour stocker toutes les données récupérées
    let allAlerts = [];

    // Je lance la récupération asynchrone de mes données JSON
    async function fetchThreatData() {
        try {
            // Puisque ce sera hébergé sur GitHub Pages ou en statique, je pointe vers le rep parent
            const response = await fetch('../data/data.json', { cache: "no-store" });
            
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

    // Je lance ma requête initiale
    fetchThreatData();
});
