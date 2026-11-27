// Create page: encrypt in the browser, store only the ciphertext, show the link.

// The server vtss talks to when none is given. On any other instance the
// snippet adds --server so the copied command reaches this one.
const PUBLIC_SERVER = "https://secretshare.valentorassa.com";
// The server's default MAX_CIPHERTEXT_BYTES; checked here so an oversized
// secret gets a clear message instead of a rejected upload.
const MAX_CIPHERTEXT = 256 * 1024;

$("#kbd").textContent = /Mac|iPhone|iPad/.test(navigator.platform || "") ? "⌘↵" : "Ctrl ↵";
$("#cli-install").textContent = `curl -fsSL ${location.origin}/install.sh | sh`;
if (location.origin !== PUBLIC_SERVER) $("#cli-send").textContent = `echo "s3cr3t" | vtss --server ${location.origin}`;

// WebCrypto only exists on HTTPS (and localhost).
const canEncrypt = Boolean(window.crypto && crypto.subtle);
if (!canEncrypt) { $("#create").disabled = true; setError("err_insecure"); }

let expiresAt = null;
function renderExpiry() {
  if (expiresAt) $("#expires").replaceChildren(...expiryNodes(expiresAt, "expires_post"));
}
VT.onChange(renderExpiry);

function setBusy(busy) {
  $("#create").disabled = busy || !canEncrypt;
  setLabel($("#create"), busy ? "btn_create_busy" : "btn_create");
}

$("#compose").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const secret = $("#secret").value;
  if (!canEncrypt) return;
  setError();
  if (!secret.trim()) { setError("err_empty"); $("#secret").focus(); return; }

  setBusy(true);
  try {
    const { ciphertext, keyFragment } = await vtEncrypt(secret);   // key stays in-browser
    if (ciphertext.length > MAX_CIPHERTEXT) { setError("err_too_large"); return; }
    const verifier_hash = await vtVerifierHash(keyFragment);        // proves the key on reveal
    const ttl = parseInt(document.querySelector('input[name="ttl"]:checked').value, 10);

    let res;
    try {
      res = await fetch("/api/secret", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ciphertext, ttl_seconds: ttl, verifier_hash }),
      });
    } catch (_) { setError("err_network"); return; }
    if (res.status === 413) { setError("err_too_large"); return; }
    if (res.status === 429) { setError("err_rate", { s: res.headers.get("Retry-After") || "60" }); return; }
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      setError("err_create", { m: e.error || "HTTP " + res.status });
      return;
    }
    const data = await res.json();

    // The link is just /s/<id>#<key>: no query string, so it survives being
    // pasted unquoted into a shell.
    const url = new URL(data.share_url || `/s/${data.id}`, location.origin);
    url.hash = keyFragment;
    $("#link").value = url.href;
    expiresAt = data.expires_at;
    renderExpiry();
    $("#secret").value = "";
    setState("done");
    $("#copy").focus();
  } catch (e) {
    setError("err_create", { m: e.message });
  } finally {
    setBusy(false);
  }
});

// Enter adds a line in the textarea; Cmd/Ctrl+Enter creates the link.
$("#secret").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && (ev.metaKey || ev.ctrlKey)) { ev.preventDefault(); $("#compose").requestSubmit(); }
});

$("#link").addEventListener("focus", (ev) => ev.target.select());
$("#copy").addEventListener("click", () => copyWithFeedback($("#copy"), $("#link").value));

$("#again").addEventListener("click", () => {
  setError();
  $("#link").value = "";
  expiresAt = null;
  setState("compose");
  $("#secret").focus();
});
