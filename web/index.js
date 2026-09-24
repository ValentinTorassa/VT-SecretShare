// Create page: encrypt in the browser, store only the ciphertext, show the link.
const $ = s => document.querySelector(s);

// typewriter that restarts on language change (instant in pro mode)
let typeToken = 0;
function startType(text){
  if (window.THEME && THEME.pro) { $("#typed").textContent = text; return; }
  const my = ++typeToken; let i = 0;
  (function tick(){ if(my!==typeToken) return; if(i<=text.length){ $("#typed").textContent = text.slice(0,i++); setTimeout(tick, 34);} })();
}
VT.onChange(() => startType(VT.t("typed_index")));
THEME.onChange(() => startType(VT.t("typed_index")));

$("#create").addEventListener("click", async () => {
  const secret = $("#secret").value;
  const errEl = $("#err"); errEl.textContent = "";
  if (!secret.trim()) { errEl.textContent = VT.t("err_empty"); return; }

  $("#create").disabled = true;
  $("#create").textContent = VT.t("btn_create_busy");

  const effectsEnabled = !THEME.pro && !matchMedia("(prefers-reduced-motion: reduce)").matches;
  let animDone = Promise.resolve();
  if (effectsEnabled) {
    $("#cipherlbl").textContent = VT.t("cipher_label");
    $("#cipherfx").classList.add("show");
    window.__vault?.pulse();
    animDone = new Promise(r => VTAnim.cipherStream($("#cipherstream"), $("#cipherbar"), 1300, r));
  }

  try {
    const { ciphertext, keyFragment } = await vtEncrypt(secret);   // key stays in-browser
    const ttl = parseInt($("#ttl").value, 10);
    const res = await fetch("/api/secret", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext, ttl_seconds: ttl }),
    });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.error || ("HTTP "+res.status)); }
    const data = await res.json();

    await animDone;                          // let the animation finish for effect
    $("#cipherfx").classList.remove("show");

    const url = new URL(data.share_url || `/s/${data.id}`, location.origin);
    url.searchParams.set("theme", THEME.val);
    url.searchParams.set("lang", VT.lang);
    url.hash = keyFragment;
    $("#link").value = url.href;
    const expires = document.createElement("span");
    expires.className = "when";
    expires.textContent = new Date(data.expires_at).toLocaleString();
    $("#meta").replaceChildren(VT.t("meta_pre"), expires, VT.t("meta_post"));
    $("#result").classList.add("show");
    $("#secret").value = "";
    window.__vault && window.__vault.pulse();
  } catch (e) {
    $("#cipherfx").classList.remove("show");
    errEl.textContent = VT.t("err_prefix") + e.message;
  } finally {
    $("#create").disabled = false;
    $("#create").textContent = VT.t("btn_create");
  }
});

$("#copy").addEventListener("click", async () => {
  try {
    await vtCopyText($("#link").value);
    $("#copy").textContent = VT.t("copied");
  } catch (_) {
    $("#copy").textContent = VT.t("copy_failed");
  }
  setTimeout(() => $("#copy").textContent = VT.t("btn_copy"), 1200);
});
