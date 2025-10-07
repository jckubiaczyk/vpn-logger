/**
 * VPN Logger - Theme Initialization (inline in head)
 * Applique le thème sauvegardé AVANT le rendu de la page pour éviter le flash
 */
(function() {
    const storageKey = 'vpn-logger-theme';
    const savedTheme = localStorage.getItem(storageKey);

    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
})();
