(function() {
    // Stored choice wins; otherwise follow the operating system setting.
    var theme = null;
    try { theme = localStorage.getItem('theme'); } catch (e) { /* storage blocked */ }
    if (theme !== 'light' && theme !== 'dark') {
        theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    document.documentElement.setAttribute('data-theme', theme);
})();
