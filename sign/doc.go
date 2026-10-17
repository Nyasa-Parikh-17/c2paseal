// Package sign builds C2PA manifests and embeds them using
// reserve-and-backfill: a placeholder manifest of the final size is inserted
// first, then the hard-binding digest and signature are written in place.
package sign
