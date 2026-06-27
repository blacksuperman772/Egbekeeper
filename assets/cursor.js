/* EdgeKeeper custom cursor — shared across all pages that have #cursor */
(function () {
  if (!window.matchMedia('(pointer: fine)').matches) return;
  var c = document.getElementById('cursor');
  if (!c) return;
  var r = document.getElementById('cursor-ring');
  var mx = 0, my = 0, rx = 0, ry = 0;
  document.addEventListener('mousemove', function (e) { mx = e.clientX; my = e.clientY; });
  (function tick() {
    c.style.left = mx + 'px'; c.style.top = my + 'px';
    if (r) { rx += (mx - rx) * 0.12; ry += (my - ry) * 0.12; r.style.left = rx + 'px'; r.style.top = ry + 'px'; }
    requestAnimationFrame(tick);
  })();
})();
