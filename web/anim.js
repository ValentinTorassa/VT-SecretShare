// Cipher / decipher visual effects. Pure DOM + requestAnimationFrame, no deps.
const GLYPHS = "ABCDEF0123456789!<>-_/\\[]{}=+*#%&@アカサタナハマ".split("");
const rg = () => GLYPHS[(Math.random() * GLYPHS.length) | 0];

// Decrypt-style reveal: target text resolves left→right out of random glyphs.
// Used to "decode" the secret on the reveal page.
function scrambleReveal(el, finalText, duration = 1200) {
  return new Promise((res) => {
    const start = performance.now();
    const n = finalText.length;
    (function frame(now) {
      const p = Math.min(1, (now - start) / duration);
      let out = "";
      for (let i = 0; i < n; i++) {
        const c = finalText[i];
        if (c === " " || c === "\n") { out += c; continue; }
        const lock = (i / Math.max(1, n)) * 0.8; // stagger the lock-in
        out += p >= lock ? c : rg();
      }
      el.textContent = out;
      if (p < 1) requestAnimationFrame(frame);
      else { el.textContent = finalText; res(); }
    })(performance.now());
  });
}

// Churning hex/glyph stream + progress bar for the encrypt/decrypt overlay.
function cipherStream(streamEl, barEl, duration, done) {
  const start = performance.now();
  (function frame(now) {
    const p = Math.min(1, (now - start) / duration);
    const lines = [];
    for (let r = 0; r < 6; r++) {
      let s = "";
      for (let c = 0; c < 46; c++) s += rg();
      lines.push(s);
    }
    streamEl.textContent = lines.join("\n");
    if (barEl) barEl.style.width = (p * 100).toFixed(1) + "%";
    if (p < 1) requestAnimationFrame(frame);
    else { if (done) done(); }
  })(performance.now());
}

window.VTAnim = { scrambleReveal, cipherStream };
