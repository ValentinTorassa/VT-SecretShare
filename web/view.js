// View page: reveal (burns the secret on the server), then decrypt in the
// browser with the key from the #fragment.
const $ = s => document.querySelector(s);
const id = location.pathname.split("/").pop();

// The key is read once and then stripped from the address bar, so the history
// entry (which browsers sync and keep) no longer holds a usable link while the
// secret is still alive. A reload before revealing reads it back from this
// tab's sessionStorage, which is not synced and dies with the tab.
const KEY_SLOT = "vt_key:" + id;
function takeKeyFragment() {
  const fromUrl = location.hash.slice(1);
  if (fromUrl) {
    try { sessionStorage.setItem(KEY_SLOT, fromUrl); } catch (_) {}
    history.replaceState(null, "", location.pathname + location.search);
    return fromUrl;
  }
  try { return sessionStorage.getItem(KEY_SLOT) || ""; } catch (_) { return ""; }
}
function forgetKey() { try { sessionStorage.removeItem(KEY_SLOT); } catch (_) {} }
const keyFragment = takeKeyFragment();
let revealedPlaintext = "";

function showGone(text) {
  $("#ready").style.display = "none";
  $("#gone").textContent = text;
  $("#gone").classList.add("show");
}

let typeToken = 0;
function startType(text){
  if (window.THEME && THEME.pro) { $("#typed").textContent = text; return; }
  const my = ++typeToken; let i = 0;
  (function tick(){ if(my!==typeToken) return; if(i<=text.length){ $("#typed").textContent = text.slice(0,i++); setTimeout(tick, 30);} })();
}
VT.onChange(() => startType(VT.t("typed_view")));
THEME.onChange(() => startType(VT.t("typed_view")));

// Before the reveal button is pressed, ask the server (without burning) whether
// the secret still exists and until when, so a dead link says so up front.
let expiresAt = null;
function renderExpiry() {
  if (!expiresAt) return;
  const when = document.createElement("span");
  when.className = "when";
  when.textContent = new Date(expiresAt).toLocaleString();
  $("#expires").replaceChildren(VT.t("meta_pre"), when, VT.t("meta_post"));
}
VT.onChange(renderExpiry);
async function checkAlive() {
  try {
    const res = await fetch(`/api/secret/${encodeURIComponent(id)}/meta`);
    if (res.status === 404) { forgetKey(); showGone(VT.t("gone_prefix") + VT.t("gone_meta")); return; }
    if (!res.ok) return; // rate limited or storage down: the reveal will say so
    expiresAt = (await res.json()).expires_at;
    renderExpiry();
  } catch (_) {}
}

if (!keyFragment || !vtValidKeyFragment(keyFragment)) {
  showGone(VT.t(keyFragment ? "err_key_invalid" : "err_link_incomplete"));
} else {
  checkAlive();
}

$("#reveal").addEventListener("click", async () => {
  $("#reveal").disabled = true;
  $("#reveal").textContent = VT.t("btn_reveal_busy");

  $("#copy").disabled = true;
  const effectsEnabled = !THEME.pro && !matchMedia("(prefers-reduced-motion: reduce)").matches;
  let animDone = Promise.resolve();
  if (effectsEnabled) {
    $("#cipherlbl").textContent = VT.t("decipher_label");
    $("#cipherfx").classList.add("show");
    window.__vault?.pulse();
    animDone = new Promise(r => VTAnim.cipherStream($("#cipherstream"), $("#cipherbar"), 1300, r));
  }

  try {
    if (!vtValidKeyFragment(keyFragment)) throw new Error(VT.t("err_key_invalid"));
    const verifier = await vtVerifier(keyFragment);   // proves the key; server can't derive it back
    const res = await fetch(`/api/secret/${encodeURIComponent(id)}/reveal`, {
      method: "POST",
      headers: { "X-VT-Reveal": "1", "Content-Type": "application/json" },
      body: JSON.stringify({ verifier }),
    });
    if (!res.ok) {
      const e = await res.json().catch(()=>({}));
      // 429 (rate limit) and 503 (store unavailable) are refused before the
      // secret is read: it is still there, so don't say "[gone]".
      if (res.status === 429 || res.status === 503) {
        const err = new Error(VT.t("err_retry_later").replace("{s}", res.headers.get("Retry-After") || "60"));
        err.retryable = true;
        throw err;
      }
      // Wrong key: the server checked it before deleting, so nothing was lost.
      if (res.status === 403 && e.code === "wrong_key") {
        const err = new Error(VT.t("err_key_wrong"));
        err.retryable = true;
        throw err;
      }
      if (res.status === 404) forgetKey();
      throw new Error(e.error || ("HTTP "+res.status));
    }
    const { ciphertext } = await res.json();
    forgetKey();                                       // burned: the key is useless now
    revealedPlaintext = await vtDecrypt(ciphertext, keyFragment);       // decrypt in-browser

    await animDone;
    $("#cipherfx").classList.remove("show");
    $("#ready").style.display = "none";
    $("#secretbox").classList.add("show");
    window.__vault && (window.__vault.setSafe(), window.__vault.pulse());
    document.getElementById("panel").classList.remove("danger");
    if (!effectsEnabled) $("#plain").textContent = revealedPlaintext;
    else await VTAnim.scrambleReveal($("#plain"), revealedPlaintext, 1300);
    $("#plain").textContent = revealedPlaintext;
    $("#copy").disabled = false;
  } catch (e) {
    $("#cipherfx").classList.remove("show");
    $("#ready").style.display = "none";
    $("#gone").textContent = (e.retryable ? VT.t("err_prefix") : VT.t("gone_prefix")) + e.message;
    $("#gone").classList.add("show");
  }
});

$("#copy").addEventListener("click", async () => {
  if (!revealedPlaintext) return;
  try {
    await vtCopyText(revealedPlaintext);
    $("#copy").textContent = VT.t("copied_full");
  } catch (_) {
    $("#copy").textContent = VT.t("copy_failed");
  }
  setTimeout(() => $("#copy").textContent = VT.t("btn_copy_full"), 1200);
});

$("#own").addEventListener("click", () => { location.href = "/"; });
