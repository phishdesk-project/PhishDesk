# Synthetic MIME corpus

Twenty hand-authored messages for C02, using invented FableBank and `.test` domains.
No captured mail, external data or actual QR image is included. `08-inline-image`
contains deliberately fake image bytes to verify inert metadata handling.

01-04: plain, UTF-8, base64, quoted-printable. 05-08: HTML, alternatives,
attachment, inline image. 09-12: encoded subject, reply-to, forged authentication,
forwarded message. 13-17: absent/unclosed boundary, invalid base64, unknown charset,
duplicate identity header. 18-20: path-like filename, URL duplicates, missing identity.

Expected behaviors and generated depth/size/count/time adversarial cases live in
`tests/test_parsing.py`. URLs are extracted strings, never visited. QR is explicitly
`qr.not_run`; image metadata does not imply image validity or inspection.
