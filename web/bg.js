// 3D animated background — "The Vault Core".
// A glitching wireframe icosahedron suspended in a drifting particle field.
// Pure Three.js (vendored locally), additive neon, mouse parallax. Degrades
// gracefully: if WebGL is unavailable the page still works, just flat.
import * as THREE from "three";

const NEON = 0x27d07a;   // VT green
const DANGER = 0xff3b3b; // VT red

export function initVault(canvas, { accent = NEON } = {}) {
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
  } catch (e) {
    canvas.style.display = "none";
    return { pulse() {}, setDanger() {} };
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x05070c, 0.018);

  const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 100);
  camera.position.z = 9;

  const core = new THREE.Group();
  scene.add(core);

  // Wireframe shell (the "vault").
  const shellGeo = new THREE.IcosahedronGeometry(3.3, 1);
  const shell = new THREE.LineSegments(
    new THREE.WireframeGeometry(shellGeo),
    new THREE.LineBasicMaterial({ color: accent, transparent: true, opacity: 0.9 })
  );
  core.add(shell);

  // A second, larger counter-rotating ring of edges for depth.
  const ring = new THREE.LineSegments(
    new THREE.WireframeGeometry(new THREE.TorusGeometry(4.6, 0.05, 8, 60)),
    new THREE.LineBasicMaterial({ color: accent, transparent: true, opacity: 0.4 })
  );
  scene.add(ring);

  // Inner glowing solid, additive so it bleeds light.
  const inner = new THREE.Mesh(
    new THREE.IcosahedronGeometry(1.9, 0),
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.22, blending: THREE.AdditiveBlending })
  );
  core.add(inner);

  // Drifting particle field.
  const COUNT = 2200;
  const positions = new Float32Array(COUNT * 3);
  for (let i = 0; i < COUNT; i++) {
    const r = 4.5 + Math.random() * 22;
    const t = Math.random() * Math.PI * 2;
    const p = Math.acos(2 * Math.random() - 1);
    positions[i * 3] = r * Math.sin(p) * Math.cos(t);
    positions[i * 3 + 1] = r * Math.sin(p) * Math.sin(t);
    positions[i * 3 + 2] = r * Math.cos(p);
  }
  const pGeo = new THREE.BufferGeometry();
  pGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  const particles = new THREE.Points(
    pGeo,
    new THREE.PointsMaterial({ color: accent, size: 0.07, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending, depthWrite: false })
  );
  scene.add(particles);

  // Mouse parallax.
  const mouse = { x: 0, y: 0 };
  window.addEventListener("pointermove", (e) => {
    mouse.x = (e.clientX / window.innerWidth - 0.5) * 2;
    mouse.y = (e.clientY / window.innerHeight - 0.5) * 2;
  });

  function resize() {
    const w = window.innerWidth, h = window.innerHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener("resize", resize);
  resize();

  let pulse = 0;
  const clock = new THREE.Clock();
  function frame() {
    const dt = clock.getDelta();
    const t = clock.elapsedTime;
    core.rotation.x += dt * 0.12;
    core.rotation.y += dt * 0.18;
    ring.rotation.x = t * 0.5;
    ring.rotation.z = -t * 0.35;
    ring.scale.setScalar(1 + pulse * 0.5);
    particles.rotation.y -= dt * 0.03;
    // glitchy scale jitter on the inner core
    const j = 1 + Math.sin(t * 7.0) * 0.02 + pulse * 0.6;
    inner.scale.setScalar(j);
    shell.material.opacity = 0.45 + Math.abs(Math.sin(t * 1.3)) * 0.2 + pulse * 0.4;
    // ease camera toward mouse
    camera.position.x += (mouse.x * 1.6 - camera.position.x) * 0.04;
    camera.position.y += (-mouse.y * 1.6 - camera.position.y) * 0.04;
    camera.lookAt(0, 0, 0);
    pulse *= 0.92;
    renderer.render(scene, camera);
    requestAnimationFrame(frame);
  }
  frame();

  function setColor(hex) {
    shell.material.color.setHex(hex);
    ring.material.color.setHex(hex);
    inner.material.color.setHex(hex);
    particles.material.color.setHex(hex);
  }

  return {
    pulse() { pulse = 1; },
    setDanger() { setColor(DANGER); },
    setSafe() { setColor(accent); },
  };
}
