// Theme toggle functionality
(function() {
    const themeToggle = document.getElementById('themeToggle');
    const sunIcon = document.querySelector('.theme-icon-sun');
    const moonIcon = document.querySelector('.theme-icon-moon');

    // theme-init.js has already applied the stored choice or the OS
    // preference; read it from the page rather than storage so the icon is
    // right when the OS default is dark. The icon shows the mode a click
    // switches to.
    function syncThemeUI(theme) {
        const themeColor = document.querySelector('meta[name="theme-color"]');
        if (themeColor) themeColor.setAttribute('content', theme === 'dark' ? '#111827' : '#2563eb');
        if (!sunIcon || !moonIcon) return;
        sunIcon.style.display = theme === 'dark' ? 'block' : 'none';
        moonIcon.style.display = theme === 'dark' ? 'none' : 'block';
    }

    syncThemeUI(document.documentElement.getAttribute('data-theme'));

    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        document.documentElement.setAttribute('data-theme', newTheme);
        try { localStorage.setItem('theme', newTheme); } catch (e) { /* storage blocked */ }
        syncThemeUI(newTheme);
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }

    // Keep the footer copyright year current (CSP disallows inline scripts)
    const yearEl = document.getElementById('copyrightYear');
    if (yearEl) {
        yearEl.textContent = new Date().getFullYear();
    }
})();
