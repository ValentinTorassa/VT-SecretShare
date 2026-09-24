// Loads the 3D vault-core background (bg.js + Three.js) only in hacker mode and
// pauses it in pro mode. data-vault="danger" on the canvas starts it red (the
// view page). bg.js is requested with this file's own ?v= so a new build never
// pairs it with a stale cached copy.
const canvas = document.getElementById("three");
const version = new URL(import.meta.url).search;
let vault;
let loading;
async function syncVault() {
  if (window.THEME.pro) {
    canvas.style.display = "none";
    vault?.setActive(false);
    return;
  }
  canvas.style.display = "";
  loading ??= import(`/web/bg.js${version}`).then(({ initVault }) => {
    const instance = initVault(canvas);
    if (canvas.dataset.vault === "danger") instance.setDanger();
    return instance;
  });
  vault = await loading;
  window.__vault = vault;
  vault.setActive(!window.THEME.pro);
}
window.THEME.onChange(syncVault);
syncVault();
