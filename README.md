# pdf-sign

Places the signer's handwritten signature (and the date, and optionally their printed name) on ONE PDF,
like signing a printed form. Ink on the page, not a digital certificate.

The rule it enforces: one named document at a time, only when the signer says so for that document,
and the signer sees the preview before anything is signed.

## Use

```
pdf-sign look  FORM.pdf                      # read-only: pages, fields, protection, numbered signature/date places, previews
pdf-sign plan  FORM.pdf [options]            # read-only: preview PNG with the signature drawn in + a plan id
# show the signer the preview; they say yes
pdf-sign apply FORM.pdf --plan ID --yes-signer-said "<their words>"   # writes FORM.signed.pdf (mode 600)
pdf-sign fields FORM.pdf                     # list form fields; fill text fields with plan --set name=value
pdf-sign clean [--dry-run]                   # delete this tool's previews/plans older than a day
```

Plan options: `--use N` (place from look), `--anchor TEXT`, `--page N --at X,Y`, `--sig-width IN`,
`--no-date`, `--date 2026-12-01`, `--date-format FMT`, `--date-at X,Y`, `--date-anchor TEXT`,
`--name TEXT` (+ `--name-at`, `--name-anchor`), `--set field=value`, `--no-signature`.
Coordinates are points from the top-left of the page as shown (same as the previews).

## Where things live

- Code: `pdf_sign.py` (single file), venv `.venv` (pymupdf, pillow, pytest). Wrapper: `~/bin/pdf-sign`.
- Signature: `~/.config/pdf-sign/signature.png` (constant `SIGNATURE_PATH`), or the path in `PDF_SIGN_SIGNATURE`. A PNG of the handwritten signature on a transparent background, mode 600 or tighter. It lives only on the signer's machine and never in this repo (`.gitignore` refuses images and signed PDFs).
- Previews and saved plans: `~/.cache/pdf-sign/` (dir 700, files 600, names start `pdfsign-`). Plans expire with `clean`.
- Log: `~/.local/state/pdf-sign/log.jsonl`, one line per apply (no image data).

## How apply stays safe

- Plan id = hash of the input path, its SHA-256, the signature image's SHA-256 and the exact placement.
  The plan is saved; apply re-hashes it and refuses if the file, the signature or the placement changed.
- Refuses: empty/missing `--yes-signer-said`, existing output, output = input, encrypted PDFs, PDFs with
  a digital signature (ink would break it), globs and folders.
- Writes a copy, adds the stamp as an incremental update (original bytes untouched at the front),
  renders the page before/after and refuses if any ink lands outside the planned boxes, then links
  the file into place without overwriting.
- No network. Previews are the only other place the signature appears.

## Tests

```
cd ~/src/claude-workspace/pdf-sign && .venv/bin/python -m pytest -q tests
```

Tests use a generated fake scribble via `PDF_SIGN_SIGNATURE` and temp folders via
`PDF_SIGN_CACHE` / `PDF_SIGN_STATE`; the real signature is never used.

## Limits

- Scanned PDFs (no text layer): nothing is found automatically; `plan` refuses until given
  `--page N --at X,Y` read off the look preview.
- Detection is heuristics on text ("Signature", "Sign here", "Date", "X\_\_\_\_", underscore runs)
  and drawn lines; odd layouts may need `--use`, `--anchor` or `--at`.
- Text drawn onto a form field area may be hidden by the field; plan warns, use `--set` for text fields.
- Only text fields can be filled; checkboxes, choices and signature fields are not filled.

## License

AGPL-3.0 (PyMuPDF, which this uses, is AGPL-3.0 too). See LICENSE.
