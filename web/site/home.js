// The home page has no app logic. Links made before the checker moved to
// app/ (such as ?store=<url> for "Recover credentials") are forwarded there.
"use strict";

if (/[?&]store=/.test(location.search)) {
  location.replace("app/" + location.search + "#recover");
}
