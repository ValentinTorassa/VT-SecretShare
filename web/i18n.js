// Minimal ES/EN i18n. Strings tagged with data-i18n / data-i18n-ph /
// data-i18n-html are swapped in place; dynamic strings are read via VT.t().
// Choice persists in localStorage. Default ES (the channel's audience).
const DICT = {
  es: {
    typed_index: "el server nunca ve tu secreto. .env no es seguridad.",
    typed_view: "clave detectada en #fragmento. esperando autorización…",
    label_secret: "// secreto — password · token · api key",
    ph_secret: "pegá el secreto a transmitir (se cifra en este navegador)",
    label_ttl: "// autodestrucción en",
    ttl_10m: "T-10:00 · 10 minutos",
    ttl_1h: "T-60:00 · 1 hora",
    ttl_1d: "T-24:00:00 · 1 día",
    ttl_7d: "T-7d · 7 días",
    btn_create: "⛓ cifrar y generar link",
    btn_create_busy: "⛓ cifrando…",
    cipher_label: "CIFRANDO",
    label_link: "// link de un solo uso — funciona UNA vez",
    btn_copy: "copiar",
    copied: "✓ copiado",
    meta_pre: "⏳ expira: ",
    meta_post: " · o al primer acceso",
    err_empty: "[error] payload vacío.",
    foot_index: "<b>zero-knowledge</b> — la clave AES-256 se genera y queda en el <span class='c'>#fragmento</span> de la URL; nunca viaja al servidor.<br>Redis solo guarda texto cifrado y lo borra al primer acceso (<span class='c'>GETDEL</span>). — VT Security",
    warn_view: "⚠ esta transmisión se <b>destruye al abrirla</b>. Si recargás, desaparece para siempre. Tené a mano dónde pegarla.",
    btn_reveal: "⮕ descifrar y destruir",
    btn_reveal_busy: "⮕ descifrando…",
    decipher_label: "DESCIFRANDO",
    label_decrypted: "// payload descifrado — ya borrado del servidor",
    btn_copy_full: "copiar al portapapeles",
    copied_full: "✓ copiado",
    btn_create_own: "crear mi propio secreto →",
    foot_view: "el servidor entregó texto cifrado y lo borró en el mismo instante (<span class='c'>GETDEL</span>). el descifrado AES-256 pasó <b>en tu navegador</b> con la clave del <span class='c'>#fragmento</span>. — VT Security",
    err_link_incomplete: "[error] link incompleto: falta la clave (#…). Pedí el link completo.",
    err_prefix: "[error] ",
    gone_prefix: "[gone] ",
  },
  en: {
    typed_index: "the server never sees your secret. .env is not security.",
    typed_view: "key detected in #fragment. awaiting authorization…",
    label_secret: "// secret — password · token · api key",
    ph_secret: "paste the secret to transmit (encrypted in this browser)",
    label_ttl: "// self-destruct in",
    ttl_10m: "T-10:00 · 10 minutes",
    ttl_1h: "T-60:00 · 1 hour",
    ttl_1d: "T-24:00:00 · 1 day",
    ttl_7d: "T-7d · 7 days",
    btn_create: "⛓ encrypt & generate link",
    btn_create_busy: "⛓ encrypting…",
    cipher_label: "ENCRYPTING",
    label_link: "// one-time link — works ONCE",
    btn_copy: "copy",
    copied: "✓ copied",
    meta_pre: "⏳ expires: ",
    meta_post: " · or on first access",
    err_empty: "[error] empty payload.",
    foot_index: "<b>zero-knowledge</b> — the AES-256 key is generated and stays in the URL <span class='c'>#fragment</span>; it never reaches the server.<br>Redis only stores ciphertext and deletes it on first access (<span class='c'>GETDEL</span>). — VT Security",
    warn_view: "⚠ this transmission <b>self-destructs when opened</b>. If you reload, it's gone forever. Have somewhere ready to paste it.",
    btn_reveal: "⮕ decrypt & destroy",
    btn_reveal_busy: "⮕ decrypting…",
    decipher_label: "DECRYPTING",
    label_decrypted: "// decrypted payload — already deleted from server",
    btn_copy_full: "copy to clipboard",
    copied_full: "✓ copied",
    btn_create_own: "create my own secret →",
    foot_view: "the server handed over ciphertext and deleted it in the same instant (<span class='c'>GETDEL</span>). AES-256 decryption happened <b>in your browser</b> with the key from the <span class='c'>#fragment</span>. — VT Security",
    err_link_incomplete: "[error] incomplete link: missing key (#…). Ask for the full link.",
    err_prefix: "[error] ",
    gone_prefix: "[gone] ",
  },
};

const VT = {
  lang: localStorage.getItem("vt_lang") || "es",
  listeners: [],
  t(k) { return (DICT[this.lang] && DICT[this.lang][k]) ?? DICT.es[k] ?? k; },
  apply() {
    document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = this.t(el.dataset.i18n); });
    document.querySelectorAll("[data-i18n-html]").forEach((el) => { el.innerHTML = this.t(el.dataset.i18nHtml); });
    document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = this.t(el.dataset.i18nPh); });
    document.documentElement.lang = this.lang;
    document.querySelectorAll("[data-lang]").forEach((b) => b.classList.toggle("on", b.dataset.lang === this.lang));
    this.listeners.forEach((fn) => fn(this.lang));
  },
  set(lang) { this.lang = lang; localStorage.setItem("vt_lang", lang); this.apply(); },
  onChange(fn) { this.listeners.push(fn); },
};
window.VT = VT;

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-lang]").forEach((b) =>
    b.addEventListener("click", () => VT.set(b.dataset.lang))
  );
  VT.apply();
});
