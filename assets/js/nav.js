(() => {
  const nav = document.querySelector('.site-nav');
  if (!nav) return;

  const button = nav.querySelector('.nav-hamburger');
  const menu = document.getElementById('site-nav-menu');
  if (!button || !menu) return;

  const setOpen = (open) => {
    nav.setAttribute('data-open', open ? 'true' : 'false');
    button.setAttribute('aria-expanded', open ? 'true' : 'false');
    button.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  };

  setOpen(false);

  button.addEventListener('click', () => {
    const isOpen = nav.getAttribute('data-open') === 'true';
    setOpen(!isOpen);
  });

  // Close on navigation (mobile) so the menu doesn't remain open.
  menu.addEventListener('click', (e) => {
    const a = e.target && e.target.closest ? e.target.closest('a') : null;
    if (!a) return;
    setOpen(false);
  });

  // Close on escape.
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') setOpen(false);
  });

  // Close if resized to desktop.
  window.addEventListener('resize', () => {
    if (window.matchMedia('(min-width: 901px)').matches) setOpen(false);
  });
})();
