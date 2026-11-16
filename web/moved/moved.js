// The C2paSeal website moved from this address (the library repository's
// GitHub Pages site) to its own repository. This sends every old address to
// the same page there: /c2paseal/docs/cli.html -> .../c2paseal-website/docs/cli.html.
// Old links to the app with ?store=<url> open the app's Recover tab.
"use strict";
(function () {
  var site = "https://nyasa-parikh-17.github.io/c2paseal-website/";
  var path = location.pathname.replace(/^\/c2paseal(\/|$)/, "");
  var search = location.search;
  var hash = location.hash;
  if ((path === "" || path === "index.html") && /[?&]store=/.test(search)) {
    path = "app/";
    if (!hash) hash = "#recover";
  }
  location.replace(site + path + search + hash);
})();
