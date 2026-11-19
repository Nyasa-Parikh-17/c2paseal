module github.com/Nyasa-Parikh-17/c2paseal/examples

go 1.27

require (
	github.com/Nyasa-Parikh-17/c2paseal v0.7.0
	github.com/Nyasa-Parikh-17/c2paseal/watermark v0.7.0
)

require (
	github.com/digitorus/pkcs7 v0.0.0-20260914070511-d678ea5ea03f // indirect
	github.com/digitorus/timestamp v0.0.0-20260914073129-b4b58b92aa51 // indirect
	github.com/fxamacker/cbor/v2 v2.9.6 // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/image v0.48.0 // indirect
)

// Builds in this repository use the local copies. Copied elsewhere, delete
// these lines and the examples use the released versions required above.
replace (
	github.com/Nyasa-Parikh-17/c2paseal => ../
	github.com/Nyasa-Parikh-17/c2paseal/watermark => ../watermark
)
