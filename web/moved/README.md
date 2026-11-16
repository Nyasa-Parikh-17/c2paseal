# Redirect site for the old website address

The website used to be published from this repository at
`https://nyasa-parikh-17.github.io/c2paseal/`. It now lives in its own
repository, [c2paseal-website](https://github.com/Nyasa-Parikh-17/c2paseal-website),
at `https://nyasa-parikh-17.github.io/c2paseal-website/`.

The `pages` workflow publishes this folder at the old address, so old links
keep working:

- `index.html` and `404.html` (GitHub Pages serves it for any missing path)
  run `moved.js`, which sends each old address to the same page on the new
  site.
- `sw.js` retires the offline service worker that the old app registered,
  so returning visitors are not shown a cached copy of the old site.
