/*
 * Shrinks photos in the browser before upload, so saving is fast on slow connections.
 * Add  data-compress="<max pixels>"  to an <input type="file">  (and data-keep-png="1" to keep transparency).
 * If anything goes wrong the original file is uploaded unchanged.
 */
(function () {
  'use strict';
  var pending = 0, waiting = [];

  function done() {
    pending--;
    if (pending === 0) { var w = waiting; waiting = []; w.forEach(function (f) { f(); }); }
  }

  function shrink(input) {
    var file = input.files && input.files[0];
    if (!file || !/^image\/(jpeg|png|webp)$/.test(file.type)) return;
    var max = parseInt(input.getAttribute('data-compress'), 10) || 1600;
    var keepPng = input.getAttribute('data-keep-png') === '1' && file.type === 'image/png';
    pending++;
    var p = window.createImageBitmap
      ? createImageBitmap(file, { imageOrientation: 'from-image' })
      : Promise.reject(new Error('unsupported'));
    p.then(function (bmp) {
      var scale = Math.min(1, max / Math.max(bmp.width, bmp.height));
      if (scale === 1 && file.size < 300 * 1024) { done(); return; }
      var w = Math.round(bmp.width * scale), h = Math.round(bmp.height * scale);
      var c = document.createElement('canvas'); c.width = w; c.height = h;
      var ctx = c.getContext('2d');
      if (!keepPng) { ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h); }
      ctx.drawImage(bmp, 0, 0, w, h);
      var type = keepPng ? 'image/png' : 'image/jpeg';
      c.toBlob(function (blob) {
        try {
          if (blob && blob.size < file.size) {
            var ext = keepPng ? '.png' : '.jpg';
            var name = file.name.replace(/\.[^.]+$/, '') + ext;
            var dt = new DataTransfer();
            dt.items.add(new File([blob], name, { type: type }));
            input.files = dt.files;
            input.dispatchEvent(new Event('compressed', { bubbles: true }));
          }
        } catch (e) { /* keep original */ }
        done();
      }, type, 0.85);
    }).catch(function () { done(); });
  }

  document.querySelectorAll('input[type="file"][data-compress]').forEach(function (inp) {
    inp.addEventListener('change', function () { shrink(inp); });
  });

  // If the person hits Save while a photo is still being shrunk, wait for it.
  document.querySelectorAll('form').forEach(function (form) {
    if (!form.querySelector('input[type="file"][data-compress]')) return;
    form.addEventListener('submit', function (e) {
      if (pending > 0 && !form._ready) {
        e.preventDefault();
        waiting.push(function () { form._ready = true; if (form.requestSubmit) form.requestSubmit(); else form.submit(); });
      }
    });
  });
})();
