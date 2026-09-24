// View page: reveal (burns the secret on the server), then decrypt in the
// browser with the key from the #fragment.
const $ = s => document.querySelector(s);
const id = location.pathname.split("/").pop();
const keyFragment = location.hash.slice(1);
let revealedPlaintext = "";

let typeToken = 0;
function startType(text){
  if (window.THEME && THEME.pro) { $("#typed").textContent = text; return; }
  const my = ++typeToken; let i = 0;
  (function tick(){ if(my!==typeToken) return; if(i<=text.length){ $("#typed").textContent = text.slice(0,i++); setTimeout(tick, 30);} })();
}
VT.onChange(() => startType(VT.t("typed_view")));
THEME.onChange(() => startType(VT.t("typed_view")));

if (!keyFragment || !vtValidKeyFragment(keyFragment)) {
  $("#ready").style.display = "none";
  $("#gone").textContent = VT.t(keyFragment ? "err_key_invalid" : "err_link_incomplete");
  $("#gone").classList.add("show");
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
    const res = await fetch(`/api/secret/${encodeURIComponent(id)}/reveal`, {
      method: "POST",
      headers: { "X-VT-Reveal": "1" },
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
      throw new Error(e.error || ("HTTP "+res.status));
    }
    const { ciphertext } = await res.json();
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
