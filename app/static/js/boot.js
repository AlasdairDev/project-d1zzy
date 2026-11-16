/* Runs synchronously in <head> (tiny, local, no inline script needed under the CSP).
 *
 * html.js       JavaScript is on: images may start transparent and fade in.
 * html.icons-ok the Material Symbols font really loaded. Without it (Tor Browser blocks web
 *               fonts from "Safer" up) icons would render as their ligature names, so CSS
 *               keeps them hidden and shows text labels instead.
 * img.loaded    set when an image finishes (or fails) loading, for the fade-in. */
(function () {
  "use strict";
  var root = document.documentElement;
  root.classList.add("js");

  if (document.fonts && document.fonts.load) {
    document.fonts.load('20px "Material Symbols Rounded"', "search").then(function (faces) {
      if (faces.length) root.classList.add("icons-ok");
    }, function () { /* font blocked: keep text labels */ });
  }

  function markLoaded(ev) {
    var el = ev.target;
    if (el && el.tagName === "IMG") el.classList.add("loaded");
  }
  // load/error do not bubble, but they can be captured on the document.
  document.addEventListener("load", markLoaded, true);
  document.addEventListener("error", markLoaded, true);
  document.addEventListener("DOMContentLoaded", function () {
    var imgs = document.images;
    for (var i = 0; i < imgs.length; i++) {
      if (imgs[i].complete) imgs[i].classList.add("loaded");
    }
  });
})();
