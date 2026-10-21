# Yubico PIV attestation trust anchors

These public certificates were retrieved from Yubico's [PIV attestation documentation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html). `manifest.json` records the exact HTTPS source and SHA-256 of each downloaded file. The provider also pins these hashes in code; it never downloads certificates while verifying a device.

`yubico-piv-ca-1.pem` is the legacy PIV root. `yubico-ca-1.pem` is Attestation Root 1 for the newer hierarchy, introduced for firmware 5.7.4 and later. `yubico-intermediate.pem` is Yubico's published intermediate bundle; intermediates are chain candidates, never independent trust anchors. Preview, user-supplied and self-signed attestation roots are not accepted.

A root update requires reviewing Yubico's primary publication, the new certificate fingerprints and provider tests, then updating the reviewed source and pins together. No automatic trust-store refresh is performed. Manufacturer key attestation proves key provenance; it does not attest the Mac's operating system or certify the application as an HSM.
