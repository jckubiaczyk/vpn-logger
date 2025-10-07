/**
 * VPN Logger - Dark Mode Manager v2.2.1
 * Gestion du thème sombre avec sauvegarde localStorage
 */

class DarkModeManager {
    constructor() {
        this.storageKey = 'vpn-logger-theme';
        this.theme = this.getStoredTheme() || 'light';
        this.init();
    }

    /**
     * Initialiser le dark mode
     */
    init() {
        // Appliquer le thème sauvegardé
        this.applyTheme(this.theme);

        // Créer le toggle si il n'existe pas
        this.createToggle();

        // Écouter les changements
        this.setupListeners();
    }

    /**
     * Récupérer le thème depuis localStorage
     */
    getStoredTheme() {
        try {
            return localStorage.getItem(this.storageKey);
        } catch (e) {
            console.warn('localStorage non disponible:', e);
            return null;
        }
    }

    /**
     * Sauvegarder le thème dans localStorage
     */
    saveTheme(theme) {
        try {
            localStorage.setItem(this.storageKey, theme);
        } catch (e) {
            console.warn('Impossible de sauvegarder le thème:', e);
        }
    }

    /**
     * Appliquer le thème
     */
    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        this.theme = theme;
        this.saveTheme(theme);

        // Mettre à jour Chart.js si présent
        if (typeof Chart !== 'undefined') {
            this.updateChartTheme(theme);
        }
    }

    /**
     * Basculer entre light et dark
     */
    toggle() {
        const newTheme = this.theme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
    }

    /**
     * Créer le bouton toggle dans le header
     */
    createToggle() {
        // Chercher le conteneur des nav-links
        const navLinks = document.querySelector('.nav-links');
        if (!navLinks) return;

        // Vérifier si le toggle existe déjà
        if (document.querySelector('.dark-mode-toggle')) return;

        // Créer le toggle
        const toggle = document.createElement('div');
        toggle.className = 'dark-mode-toggle';
        toggle.setAttribute('role', 'button');
        toggle.setAttribute('aria-label', 'Basculer le mode sombre');
        toggle.setAttribute('tabindex', '0');
        toggle.title = 'Basculer le mode sombre';

        // Ajouter l'événement click
        toggle.addEventListener('click', () => this.toggle());

        // Support clavier
        toggle.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.toggle();
            }
        });

        // Insérer comme premier élément des nav-links
        navLinks.insertBefore(toggle, navLinks.firstChild);
    }

    /**
     * Setup event listeners
     */
    setupListeners() {
        // Écouter les changements de préférence système (optionnel)
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            mediaQuery.addEventListener('change', (e) => {
                // Ne changer automatiquement que si l'utilisateur n'a pas de préférence sauvegardée
                if (!this.getStoredTheme()) {
                    this.applyTheme(e.matches ? 'dark' : 'light');
                }
            });
        }
    }

    /**
     * Mettre à jour le thème des graphiques Chart.js
     */
    updateChartTheme(theme) {
        const isDark = theme === 'dark';

        if (typeof Chart !== 'undefined' && Chart.defaults) {
            Chart.defaults.color = isDark ? '#d1d5db' : '#4b5563';
            Chart.defaults.borderColor = isDark ? '#374151' : '#e5e7eb';

            // Recharger les graphiques si la fonction existe
            if (typeof loadStatistics === 'function') {
                // Pour la page statistics
                setTimeout(() => loadStatistics(), 100);
            }

            if (typeof loadCalendar === 'function') {
                // Pour la page calendar
                setTimeout(() => loadCalendar(), 100);
            }
        }
    }
}

// Initialiser le dark mode dès que le DOM est prêt
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.darkMode = new DarkModeManager();
    });
} else {
    window.darkMode = new DarkModeManager();
}
