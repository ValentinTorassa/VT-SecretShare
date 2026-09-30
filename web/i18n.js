// Minimal ES/EN i18n. Strings tagged with data-i18n / data-i18n-ph /
// data-i18n-rich are built with DOM nodes; dynamic strings are read via VT.t().
// Choice persists in localStorage. A valid ?lang= query pins the receiver's
// initial language so shared links render exactly as the sender intended.
const _langQP = new URLSearchParams(location.search).get("lang");
const _initialLang = (_langQP === "es" || _langQP === "en")
  ? _langQP
  : (localStorage.getItem("vt_lang") || "es");

const DICT = {
  es: {
    typed_index: "el server nunca ve tu secreto. .env no es seguridad.",
    typed_view: "clave detectada en #fragmento. esperando autorización…",
    label_secret: "// secreto - password · token · api key",
    ph_secret: "pegá el secreto a transmitir (se cifra en este navegador)",
    label_ttl: "// autodestrucción en",
    ttl_10m: "T-10:00 · 10 minutos",
    ttl_1h: "T-60:00 · 1 hora",
    ttl_1d: "T-24:00:00 · 1 día",
    ttl_7d: "T-7d · 7 días",
    btn_create: "⛓ cifrar y generar link",
    btn_create_busy: "⛓ cifrando…",
    cipher_label: "CIFRANDO",
    label_link: "// link de un solo uso - funciona UNA vez",
    btn_copy: "copiar",
    copied: "✓ copiado",
    meta_pre: "⏳ expira: ",
    meta_post: " · o al primer acceso",
    err_empty: "[error] payload vacío.",
    btn_reveal: "⮕ descifrar y destruir",
    btn_reveal_busy: "⮕ descifrando…",
    decipher_label: "DESCIFRANDO",
    label_decrypted: "// payload descifrado - ya borrado del servidor",
    btn_copy_full: "copiar al portapapeles",
    copied_full: "✓ copiado",
    copy_failed: "error al copiar",
    btn_create_own: "crear mi propio secreto →",
    err_link_incomplete: "[error] link incompleto: falta la clave (#…). Pedí el link completo.",
    err_key_invalid: "[error] link inválido: la clave del #fragmento no es válida.",
    err_prefix: "[error] ",
    gone_prefix: "[gone] ",
    err_retry_later: "demasiados intentos. El secreto sigue intacto: recargá en {s} segundos.",
    err_key_wrong: "la clave del link no coincide con este secreto. No se abrió y sigue intacto: revisá que copiaste el link completo.",
    gone_meta: "este secreto ya no existe: link equivocado, vencido o ya leído.",
  },
  en: {
    typed_index: "the server never sees your secret. .env is not security.",
    typed_view: "key detected in #fragment. awaiting authorization…",
    label_secret: "// secret - password · token · api key",
    ph_secret: "paste the secret to transmit (encrypted in this browser)",
    label_ttl: "// self-destruct in",
    ttl_10m: "T-10:00 · 10 minutes",
    ttl_1h: "T-60:00 · 1 hour",
    ttl_1d: "T-24:00:00 · 1 day",
    ttl_7d: "T-7d · 7 days",
    btn_create: "⛓ encrypt & generate link",
    btn_create_busy: "⛓ encrypting…",
    cipher_label: "ENCRYPTING",
    label_link: "// one-time link - works ONCE",
    btn_copy: "copy",
    copied: "✓ copied",
    meta_pre: "⏳ expires: ",
    meta_post: " · or on first access",
    err_empty: "[error] empty payload.",
    btn_reveal: "⮕ decrypt & destroy",
    btn_reveal_busy: "⮕ decrypting…",
    decipher_label: "DECRYPTING",
    label_decrypted: "// decrypted payload - already deleted from server",
    btn_copy_full: "copy to clipboard",
    copied_full: "✓ copied",
    copy_failed: "copy failed",
    btn_create_own: "create my own secret →",
    err_link_incomplete: "[error] incomplete link: missing key (#…). Ask for the full link.",
    err_key_invalid: "[error] invalid link: the key in the #fragment is malformed.",
    err_prefix: "[error] ",
    gone_prefix: "[gone] ",
    err_retry_later: "too many attempts. The secret is still intact: reload in {s} seconds.",
    err_key_wrong: "the key in this link doesn't match this secret. It was not opened and is still intact: check you copied the whole link.",
    gone_meta: "this secret no longer exists: wrong link, expired, or already viewed.",
  },
};

const RICH = {
  es: {
    foot_index: [["b", "zero-knowledge"], " - la clave AES-256 se genera y queda en el ", ["span", "#fragmento"], " de la URL; nunca viaja al servidor.", ["br"], "Redis solo guarda texto cifrado y lo borra al primer acceso con la clave correcta (", ["span", "lectura y borrado atómicos"], "). - VT Security"],
    warn_view: ["⚠ esta transmisión se ", ["b", "destruye al abrirla"], ". Si recargás, desaparece para siempre. Tené a mano dónde pegarla."],
    foot_view: ["el servidor entregó texto cifrado y lo borró en el mismo instante (", ["span", "lectura y borrado atómicos"], "). el descifrado AES-256 pasó ", ["b", "en tu navegador"], " con la clave del ", ["span", "#fragmento"], ". - VT Security"],
  },
  en: {
    foot_index: [["b", "zero-knowledge"], " - the AES-256 key is generated and stays in the URL ", ["span", "#fragment"], "; it never reaches the server.", ["br"], "Redis only stores ciphertext and deletes it on the first access with the right key (", ["span", "atomic read-and-delete"], "). - VT Security"],
    warn_view: ["⚠ this transmission ", ["b", "self-destructs when opened"], ". If you reload, it's gone forever. Have somewhere ready to paste it."],
    foot_view: ["the server handed over ciphertext and deleted it in the same instant (", ["span", "atomic read-and-delete"], "). AES-256 decryption happened ", ["b", "in your browser"], " with the key from the ", ["span", "#fragment"], ". - VT Security"],
  },
};

// Only these elements can come out of RICH, and never with attributes (the
// span gets a fixed class), so even an edited dictionary cannot inject markup.
const RICH_TAGS = new Set(["b", "span", "br"]);
function richNode(part) {
  if (typeof part === "string") return document.createTextNode(part);
  if (!Array.isArray(part) || !RICH_TAGS.has(part[0])) return document.createTextNode(Array.isArray(part) ? String(part[1] ?? "") : "");
  const node = document.createElement(part[0]);
  if (part[0] === "span") node.className = "c";
  if (part[1]) node.textContent = part[1];
  return node;
}

const VT = {
  lang: _initialLang,
  listeners: [],
  t(k) { return (DICT[this.lang] && DICT[this.lang][k]) ?? DICT.es[k] ?? k; },
  apply() {
    document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = this.t(el.dataset.i18n); });
    document.querySelectorAll("[data-i18n-rich]").forEach((el) => {
      const parts = RICH[this.lang]?.[el.dataset.i18nRich] ?? RICH.es[el.dataset.i18nRich] ?? [];
      el.replaceChildren(...parts.map(richNode));
    });
    document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = this.t(el.dataset.i18nPh); });
    document.documentElement.lang = this.lang;
    document.querySelectorAll("[data-lang]").forEach((b) => b.classList.toggle("on", b.dataset.lang === this.lang));
    this.listeners.forEach((fn) => fn(this.lang));
  },
  set(lang) { this.lang = lang; localStorage.setItem("vt_lang", lang); this.apply(); },
  onChange(fn) { this.listeners.push(fn); },
};
window.VT = VT;

if (_langQP === "es" || _langQP === "en") localStorage.setItem("vt_lang", _langQP);
document.querySelectorAll("[data-lang]").forEach((b) =>
  b.addEventListener("click", () => VT.set(b.dataset.lang))
);
VT.apply();
