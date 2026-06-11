// UI mode: "hacker" (default, full 3D + animations) vs "pro" (sober, mostly
// static — for sharing secrets with companies/colleagues). Sets a data-theme on
// <html> (CSS does the visual switch) and pauses the heavy fx loops in pro mode.
// A ?theme=pro|hacker query param overrides (and pins) the stored choice — handy
// for linking colleagues straight into the sober UI.
const _qp = new URLSearchParams(location.search).get("theme");
const THEME = {
  val: (_qp === "pro" || _qp === "hacker") ? _qp : (localStorage.getItem("vt_theme") || "hacker"),
  listeners: [],
  get pro() { return this.val === "pro"; },
  apply() {
    document.documentElement.dataset.theme = this.val;
    document.querySelectorAll("[data-theme-set]").forEach((b) =>
      b.classList.toggle("on", b.dataset.themeSet === this.val)
    );
    if (window.__vault) window.__vault.setActive(!this.pro);
    if (window.__matrix) window.__matrix.setActive(!this.pro);
    this.listeners.forEach((fn) => fn(this.val));
  },
  set(v) { this.val = v; localStorage.setItem("vt_theme", v); this.apply(); },
  onChange(fn) { this.listeners.push(fn); },
};
window.THEME = THEME;

document.addEventListener("DOMContentLoaded", () => {
  if (_qp === "pro" || _qp === "hacker") localStorage.setItem("vt_theme", _qp);
  document.querySelectorAll("[data-theme-set]").forEach((b) =>
    b.addEventListener("click", () => THEME.set(b.dataset.themeSet))
  );
  THEME.apply();
});
