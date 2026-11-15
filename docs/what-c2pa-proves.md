# What C2PA does and does not prove

Content Credentials are often described as a way to tell real pictures
from fake ones. They are not. This page explains what a verified result
from C2paSeal, or any C2PA validator, tells you, and what it doesn't.

## What a "Trusted" result does prove

When C2paSeal reports **Trusted**:

1. **Someone holding a certificate signed this.** The claim was signed with
   the private key for a certificate that chains to a trust anchor you
   chose, such as the official C2PA trust list.
2. **The file has not changed since.** The hard binding (a hash over the
   image bytes) matches. Changing one byte of the picture makes it
   **Invalid**.
3. **The manifest has not changed since.** Every assertion (the actions,
   the ingredients, the title) is covered by the signature.
4. **The history is intact as recorded.** Earlier manifests in the file
   are kept byte for byte, and their links are checked.

## What it does not prove

- **That the picture is true.** C2PA records what the signer *claims*
  happened: "captured with this camera", "edited in this app". A signer can
  sign a staged scene, a photo of a screen, or a generated image labelled
  as a capture. The signature proves who made the claim, not that the claim
  is correct.
- **Who is in the picture, or where and when it was taken.** Unless a
  trustworthy device or app recorded those and signed them, they are just
  what someone said.
- **That the signer is honest or careful.** A trust list says a CA checked
  the signer's identity. It doesn't vouch for their intentions. A service
  that signs every upload (such as [sealsvc](sealsvc.md) or the
  [middleware](middleware.md)) vouches only that *it received* the file.
- **When it was signed, without a time-stamp.** The signing time in a
  manifest without an RFC 3161 time-stamp is the signer's own clock. A
  time-stamp from a trusted authority fixes the time independently.
- **That nothing was left out.** A manifest describes what the signing
  software chose to record. Absent actions are not proof that nothing else
  happened.

## What a missing or broken result means

- **No credentials (Invalid, `claim.missing`)** is not evidence of
  manipulation. Most images have none, and most platforms strip them on
  upload.
- **Invalid with `assertion.dataHash.mismatch`** means the bytes changed
  after signing. That might be malicious, or it might be a harmless
  re-save by software that does not understand C2PA.
- **Valid but not Trusted** means intact, but you have not told the
  validator to trust that signer. Anyone can make a certificate. Until it
  chains to a trust anchor, the name in it is unverified.

## A recovered result

A credential recovered through a [watermark](watermark.md) means: "this
copy carries the watermark of a picture whose credentials are these". The
copy itself is not the signed file, and it never verifies as unchanged.
Watermarks can be read, removed or, by someone with the code, copied onto
another picture. Treat the match as a lead, not proof.

## The test certificates

C2paSeal's repository includes a TEST ONLY certificate authority whose
private keys are public. Anything signed with it proves nothing at all,
which is why validators report it as untrusted unless told otherwise.

## So what is it good for?

Provenance you can check: a news organisation can show that a picture is
the one its photographer filed, a brand can show which images it
published, and a platform can show what an image said about itself when
uploaded. It works best as *positive* evidence from signers you have reason
to trust. Missing credentials prove nothing either way.
