// View page: reveal (burns the secret on the server), then decrypt in the
// browser with the key from the #fragment.
//
// States: checking (asking the server, nothing shown yet) -> ready -> revealed,
// or one of the dead ends: gone, badlink, wrongkey, undecryptable.
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

let expiresAt = null;
function renderExpiry() {
  if (!expiresAt) return;
  $("#expires").replaceChildren(...expiryNodes(expiresAt));
  $("#expires-row").hidden = false;
}
VT.onChange(renderExpiry);

// Before the button can be pressed, ask the server (without burning) whether
// the secret still exists and until when, so a dead link says so up front. If
// the answer is slow, rate limited or the store is down, the page goes to
// ready anyway and the reveal reports what happened.
async function checkAlive() {
  const giveUp = setTimeout(() => { if (getState() === "checking") setState("ready"); }, 1500);
  try {
    const res = await fetch(`/api/secret/${encodeURIComponent(id)}/meta`);
    if (res.status === 404) {
      if (getState() === "checking" || getState() === "ready") { forgetKey(); setState("gone"); }
      return;
    }
    if (res.ok) { expiresAt = (await res.json()).expires_at; renderExpiry(); }
  } catch (_) {
  } finally {
    clearTimeout(giveUp);
    if (getState() === "checking") setState("ready");
  }
}

if (!keyFragment || !vtValidKeyFragment(keyFragment)) setState("badlink");
else checkAlive();

// Opening the link again in the same tab only changes the #fragment: the page
// does not reload, and the key would sit in the address bar. Once the secret
// is on screen just strip it; otherwise reload, so a full link pasted over a
// broken one is read (and stripped) like a fresh visit.
addEventListener("hashchange", () => {
  if (!location.hash) return;
  if (getState() === "revealed") history.replaceState(null, "", location.pathname + location.search);
  else location.reload();
});

function setBusy(busy) {
  $("#reveal").disabled = busy;
  setLabel($("#reveal"), busy ? "btn_reveal_busy" : "btn_reveal");
}

$("#reveal").addEventListener("click", async () => {
  setError();
  setBusy(true);
  try {
    const verifier = await vtVerifier(keyFragment);   // proves the key; server can't derive it back
    let res;
    try {
      res = await fetch(`/api/secret/${encodeURIComponent(id)}/reveal`, {
        method: "POST",
        headers: { "X-VT-Reveal": "1", "Content-Type": "application/json" },
        body: JSON.stringify({ verifier }),
      });
    } catch (_) { setError("err_network"); return; }

    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      // 429 (rate limit) and 503 (store unavailable) are refused before the
      // secret is read: it is still there, and the button stays to try again.
      if (res.status === 429 || res.status === 503) {
        setError("err_retry_later", { s: res.headers.get("Retry-After") || "60" });
        return;
      }
      // Wrong key: the server checked it before deleting, so nothing was lost.
      if (res.status === 403 && e.code === "wrong_key") { setState("wrongkey"); return; }
      if (res.status === 404) { forgetKey(); setState("gone"); return; }
      setError("err_reveal", { m: e.error || "HTTP " + res.status });
      return;
    }

    const { ciphertext } = await res.json();
    forgetKey();                                       // burned: the key is useless now
    try {
      revealedPlaintext = await vtDecrypt(ciphertext, keyFragment);   // decrypt in-browser
    } catch (_) {
      // Only a secret stored without a verifier gets here: it burned on a
      // reveal whose key could not open it.
      setState("undecryptable");
      return;
    }
    $("#plain").textContent = revealedPlaintext;
    setState("revealed");
    $("#copy").focus();
  } catch (e) {
    setError("err_reveal", { m: e.message });
  } finally {
    setBusy(false);
  }
});

$("#copy").addEventListener("click", () => {
  if (revealedPlaintext) copyWithFeedback($("#copy"), revealedPlaintext);
});
