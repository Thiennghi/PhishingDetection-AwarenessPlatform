/* CyberGuard light/dark theme toggle. Saved in localStorage; falls back to the device preference. */
(function () {
  var root = document.documentElement;
  var themeBtn = null;

  function setTheme(t) {
    root.setAttribute('data-theme', t);
    if (themeBtn) {
      themeBtn.textContent = t === 'dark' ? '☀️' : '🌙';
      themeBtn.setAttribute('aria-label', t === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
      themeBtn.setAttribute('title', t === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    }
  }

  // Apply the theme immediately (script runs in <head>) so the page does not flash the wrong colours.
  var saved = null;
  try { saved = localStorage.getItem('theme'); } catch (e) {}
  if (saved !== 'dark' && saved !== 'light') saved = null;
  var prefersDark = !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  setTheme(saved || (prefersDark ? 'dark' : 'light'));

  document.addEventListener('DOMContentLoaded', function () {
    themeBtn = document.getElementById('themeToggle');
    if (!themeBtn) return;
    setTheme(root.getAttribute('data-theme'));
    themeBtn.addEventListener('click', function () {
      var t = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      setTheme(t);
      try { localStorage.setItem('theme', t); } catch (e) {}
    });
  });
})();