(() => {
  const menu = document.getElementById('mobile-menu');
  const openBtn = document.querySelector('.nav-hamburger');
  if (!menu || !openBtn) return;
  const closeBtn = document.getElementById('mobile-menu-close');

  const setOpen = (open) => {
    menu.classList.toggle('is-open', open);
    document.body.classList.toggle('menu-open', open);
    menu.setAttribute('aria-hidden', open ? 'false' : 'true');
    openBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    openBtn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  };
  setOpen(false);

  openBtn.addEventListener('click', () => setOpen(true));
  if (closeBtn) closeBtn.addEventListener('click', () => setOpen(false));

  // Trends accordion
  const trendsToggle = document.getElementById('m-trends-toggle');
  const trendsPanel = document.getElementById('m-trends-panel');
  if (trendsToggle && trendsPanel) {
    trendsToggle.addEventListener('click', () => {
      const expanded = trendsToggle.getAttribute('aria-expanded') === 'true';
      trendsToggle.setAttribute('aria-expanded', expanded ? 'false' : 'true');
      trendsPanel.classList.toggle('is-open', !expanded);
    });
  }

  // Close when a link is tapped (page navigates), on Escape, and on resize to desktop.
  menu.addEventListener('click', (e) => {
    const a = e.target.closest ? e.target.closest('a') : null;
    if (a) setOpen(false);
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') setOpen(false); });
  window.addEventListener('resize', () => {
    if (window.matchMedia('(min-width: 901px)').matches) setOpen(false);
  });
})();
