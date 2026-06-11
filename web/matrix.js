// Matrix digital rain on a 2D canvas, layered over the 3D scene.
(function () {
  const canvas = document.getElementById("matrix");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const glyphs = "アカサタナハマヤラワ0123456789ABCDEF<>/\\{}#$%&*+=¥".split("");
  let cols, drops, fontSize;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    fontSize = Math.max(12, Math.round(window.innerWidth / 90));
    cols = Math.floor(canvas.width / fontSize);
    drops = Array(cols).fill(0).map(() => Math.random() * -50);
  }
  window.addEventListener("resize", resize);
  resize();

  let active = true, rafId = 0;
  function draw() {
    ctx.fillStyle = "rgba(5,7,12,0.10)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = fontSize + "px monospace";
    for (let i = 0; i < cols; i++) {
      const ch = glyphs[(Math.random() * glyphs.length) | 0];
      const x = i * fontSize;
      const y = drops[i] * fontSize;
      // bright leading glyph, dim trail
      ctx.fillStyle = Math.random() > 0.975 ? "#aaffcc" : "#27d07a";
      ctx.fillText(ch, x, y);
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i] += 0.5;
    }
    rafId = requestAnimationFrame(draw);
  }
  // Pro mode stops the rain.
  function setActive(on) {
    if (on === active) return;
    active = on;
    if (on) draw(); else cancelAnimationFrame(rafId);
  }
  window.__matrix = { setActive };
  draw();
  if (window.THEME && window.THEME.pro) setActive(false);
})();
