// Black by default; the header toggle switches to light and back. A choice is
// kept in localStorage and set as data-theme on <html>. Loaded in <head>, so
// a stored light theme applies before first paint.
//
// Links made before v1.1 carry ?theme=hacker|pro and browsers may still hold
// those values in storage. Both are ignored: there is one UI now.
const THEME = {
  get stored() {
    try {
      const v = localStorage.getItem("vt_theme");
      return v === "light" || v === "dark" ? v : null;
    } catch (_) { return null; }
  },
  get current() { return document.documentElement.dataset.theme || "dark"; },
  toggle() {
    const next = this.current === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("vt_theme", next); } catch (_) {}
  },
};
window.THEME = THEME;
if (THEME.stored) document.documentElement.dataset.theme = THEME.stored;

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("theme")?.addEventListener("click", () => THEME.toggle());
});
