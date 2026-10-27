// Beacon landing page: hands the link (still only in the URL fragment) to the app.
(function () {
  var hash = location.hash;
  var open = document.getElementById('open');
  var get = document.getElementById('get');
  var status = document.getElementById('status');
  var dl = document.documentElement.getAttribute('data-download') || '';
  if (dl) get.href = dl; else get.style.display = 'none';
  if (!/^#v1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{40,4000}$/.test(hash)) {
    status.textContent = 'This link is incomplete or damaged. Ask the sender for a new beacon.';
    status.className = 'err';
    open.style.display = 'none';
    return;
  }
  var app = 'wekonet://b' + hash;
  open.href = app;
  // Try once automatically; browsers that need a tap will use the button.
  setTimeout(function () { location.href = app; }, 300);
})();
