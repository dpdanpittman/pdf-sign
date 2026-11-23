#!/usr/bin/env python3
"""pdf-sign: place the signer's handwritten signature and the date on ONE PDF.

This is ink on the page (like signing a printed form), not a cryptographic
signature. The flow is always: look -> plan (preview) -> the signer says yes -> apply.

No network use anywhere in this file.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import pymupdf as fitz
from PIL import Image, ImageDraw, ImageFont

TOOL_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Paths. The signature path is ONE constant; tests override it with an env var.
# ---------------------------------------------------------------------------
SIGNATURE_PATH = Path.home() / ".config/pdf-sign/signature.png"
SIGNATURE_ENV = "PDF_SIGN_SIGNATURE"          # overrides SIGNATURE_PATH (a per-machine location; the tests use a fake scribble)
CACHE_DIR = Path(os.environ.get("PDF_SIGN_CACHE", Path.home() / ".cache/pdf-sign"))
STATE_DIR = Path(os.environ.get("PDF_SIGN_STATE", Path.home() / ".local/state/pdf-sign"))
LOG_FILE = STATE_DIR / "log.jsonl"
PLAN_DIR = CACHE_DIR / "plans"

PREFIX = "pdfsign-"            # every file this tool writes in CACHE_DIR starts with this
CLEAN_AGE_SECONDS = 24 * 3600

PT_PER_IN = 72.0
DEFAULT_SIG_WIDTH_IN = 2.0
MIN_SIG_WIDTH_PT = 0.75 * PT_PER_IN
EMBED_DPI = 400                # signature is downscaled to this at its placed size (never upscaled)
DEFAULT_DATE_FORMAT = "%m/%d/%Y"
DEFAULT_FONT_SIZE = 11.0
SIG_GAP_ABOVE_LINE = 1.5       # points between the bottom of the ink and the line
LOOK_DPI = 100
PLAN_DPI = 144
VERIFY_TOLERANCE_PT = 4.0

os.umask(0o077)


class Refuse(Exception):
    """A deliberate stop with a plain-words reason."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_private_dir(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)


def write_private(path: Path, data: bytes) -> None:
    """Write a file with mode 600 (replacing a previous file of ours with the same name)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
    finally:
        os.close(fd)


def check_one_pdf(arg: str) -> Path:
    """One named, existing, regular .pdf file. No globs, no directories."""
    if not arg or not arg.strip():
        raise Refuse("No file given.")
    if any(c in arg for c in "*?[]"):
        raise Refuse(f"'{arg}' looks like a pattern. Give one exact file name; this tool works on one file at a time.")
    p = Path(arg).expanduser()
    if not p.exists():
        raise Refuse(f"File not found: {p}")
    if p.is_dir():
        raise Refuse(f"{p} is a folder. Give one PDF file; there is no batch mode.")
    if not p.is_file():
        raise Refuse(f"{p} is not a regular file.")
    if p.suffix.lower() != ".pdf":
        raise Refuse(f"{p} does not end in .pdf.")
    return p.resolve()


def fmt_rect(r) -> str:
    return f"x={r[0]:.0f}..{r[2]:.0f}, y={r[1]:.0f}..{r[3]:.0f}"


# ---------------------------------------------------------------------------
# Signature image
# ---------------------------------------------------------------------------
def signature_path() -> Path:
    override = os.environ.get(SIGNATURE_ENV)
    return Path(override).expanduser() if override else SIGNATURE_PATH


_override_noted = False


def load_signature() -> tuple[Image.Image, str, Path]:
    """Return (ink-cropped RGBA image, sha256 of the file, path). Checks permissions first."""
    p = signature_path()
    global _override_noted
    if os.environ.get(SIGNATURE_ENV) and not _override_noted:
        _override_noted = True
        print(f"note: using signature override from ${SIGNATURE_ENV} ({p})", file=sys.stderr)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        raise Refuse(f"Signature image not found at {p}. Nothing was done.")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise Refuse(f"Signature at {p} is not a plain file (symlink or other). Stopping.")
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise Refuse(f"Signature file {p} has permissions {oct(mode)}; it must be 600 or tighter. "
                     f"Fix with: chmod 600 {p}")
    if st.st_uid != os.getuid():
        raise Refuse(f"Signature file {p} is not owned by this user. Stopping.")
    raw = p.read_bytes()
    img = Image.open(io.BytesIO(raw))
    img.load()
    if img.mode not in ("RGBA", "LA") and not (img.mode == "P" and "transparency" in img.info):
        raise Refuse(f"Signature image {p} has no transparency; it must be a transparent PNG.")
    img = img.convert("RGBA")
    alpha = img.getchannel("A").point(lambda a: 255 if a > 16 else 0)
    box = alpha.getbbox()
    if not box:
        raise Refuse(f"Signature image {p} is fully transparent.")
    pad = 2
    box = (max(0, box[0] - pad), max(0, box[1] - pad), min(img.width, box[2] + pad), min(img.height, box[3] + pad))
    return img.crop(box), sha256_bytes(raw), p


def signature_png_for(img: Image.Image, width_pt: float) -> bytes:
    """PNG bytes of the signature scaled to EMBED_DPI at the placed width (never upscaled)."""
    target_px = int(round(width_pt / PT_PER_IN * EMBED_DPI))
    if target_px < img.width:
        h = max(1, int(round(img.height * target_px / img.width)))
        img = img.resize((target_px, h), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Page geometry. Everything the user sees is in "visual" coordinates:
# points from the top-left corner of the page as displayed (after /Rotate and
# the crop box), the same as the preview PNGs (preview pixels = points * dpi/72).
# Internally we read and write in PDF user space through our own formulas,
# with the page temporarily normalised (no rotation, crop box = media box).
# ---------------------------------------------------------------------------
def _num_array(s: str):
    try:
        vals = [float(x) for x in s.strip("[] ").split()]
    except ValueError:
        return None
    return vals if len(vals) == 4 else None


def _inherited(doc, xref: int, key: str):
    seen = set()
    while xref and xref not in seen:
        seen.add(xref)
        t, v = doc.xref_get_key(xref, key)
        if t != "null":
            return t, v
        t, parent = doc.xref_get_key(xref, "Parent")
        if t != "xref":
            break
        xref = int(parent.split()[0])
    return "null", "null"


def _resolve_array(doc, t, v):
    if t == "xref":
        v = doc.xref_object(int(v.split()[0]), compressed=True)
    return _num_array(v) if v and v != "null" else None


@dataclass
class Geometry:
    pno: int                   # 0-based
    xref: int
    rotation: int
    media: tuple               # PDF coords x0,y0,x1,y1
    crop: tuple
    raw_crop: tuple            # (type, value) as stored on the page object itself
    raw_rotate: tuple

    @property
    def W(self):
        return self.crop[2] - self.crop[0]

    @property
    def H(self):
        return self.crop[3] - self.crop[1]

    @property
    def visual_size(self):
        return (self.H, self.W) if self.rotation in (90, 270) else (self.W, self.H)

    # PDF user space -> visual
    def pdf_to_vis(self, x, y):
        u, v = x - self.crop[0], self.crop[3] - y
        W, H, r = self.W, self.H, self.rotation
        if r == 0:
            return u, v
        if r == 90:
            return H - v, u
        if r == 180:
            return W - u, H - v
        return v, W - u

    def vis_to_pdf(self, X, Y):
        W, H, r = self.W, self.H, self.rotation
        if r == 0:
            u, v = X, Y
        elif r == 90:
            u, v = Y, H - X
        elif r == 180:
            u, v = W - X, H - Y
        else:
            u, v = W - Y, X
        return self.crop[0] + u, self.crop[3] - v

    # normalised-page PyMuPDF space (rotation 0, crop = media): top-left of media box, y down
    def mu_to_pdf(self, x, y):
        return x + self.media[0], self.media[3] - y

    def pdf_to_mu(self, x, y):
        return x - self.media[0], self.media[3] - y

    def mu_to_vis(self, x, y):
        return self.pdf_to_vis(*self.mu_to_pdf(x, y))

    def vis_to_mu(self, X, Y):
        return self.pdf_to_mu(*self.vis_to_pdf(X, Y))

    def mu_rect_to_vis(self, r):
        pts = [self.mu_to_vis(r[0], r[1]), self.mu_to_vis(r[2], r[3])]
        return (min(p[0] for p in pts), min(p[1] for p in pts), max(p[0] for p in pts), max(p[1] for p in pts))

    def vis_rect_to_mu(self, r):
        pts = [self.vis_to_mu(r[0], r[1]), self.vis_to_mu(r[2], r[3])]
        return fitz.Rect(min(p[0] for p in pts), min(p[1] for p in pts), max(p[0] for p in pts), max(p[1] for p in pts))


def page_geometry(doc, pno: int) -> Geometry:
    page = doc[pno]
    xref = page.xref
    media = _resolve_array(doc, *_inherited(doc, xref, "MediaBox"))
    if not media:
        raise Refuse(f"Page {pno + 1} has no readable MediaBox; refusing to guess where things go.")
    media = (min(media[0], media[2]), min(media[1], media[3]), max(media[0], media[2]), max(media[1], media[3]))
    crop = _resolve_array(doc, *_inherited(doc, xref, "CropBox")) or media
    crop = (min(crop[0], crop[2]), min(crop[1], crop[3]), max(crop[0], crop[2]), max(crop[1], crop[3]))
    crop = (max(crop[0], media[0]), max(crop[1], media[1]), min(crop[2], media[2]), min(crop[3], media[3]))
    if crop[2] - crop[0] < 10 or crop[3] - crop[1] < 10:
        raise Refuse(f"Page {pno + 1} has a crop box outside its media box; refusing.")
    t, v = _inherited(doc, xref, "Rotate")
    try:
        rot = int(float(v)) if t != "null" else 0
    except ValueError:
        raise Refuse(f"Page {pno + 1} has an unreadable /Rotate value ({v}); refusing.")
    if rot % 90 != 0:
        raise Refuse(f"Page {pno + 1} has rotation {rot}, which is not a multiple of 90; refusing.")
    return Geometry(pno, xref, rot % 360, tuple(media), tuple(crop),
                    doc.xref_get_key(xref, "CropBox"), doc.xref_get_key(xref, "Rotate"))


def normalise_page(doc, g: Geometry):
    """Temporarily: rotation 0, crop box = media box. Returns a fresh Page."""
    m = g.media
    doc.xref_set_key(g.xref, "CropBox", f"[{m[0]:g} {m[1]:g} {m[2]:g} {m[3]:g}]")
    doc.xref_set_key(g.xref, "Rotate", "0")
    return doc.load_page(g.pno)


def restore_page(doc, g: Geometry):
    for key, (t, v) in (("CropBox", g.raw_crop), ("Rotate", g.raw_rotate)):
        doc.xref_set_key(g.xref, key, v if t != "null" else "null")


# ---------------------------------------------------------------------------
# Reading a document: security state, fields, text lines, candidates
# ---------------------------------------------------------------------------
WIDGET_TYPES = {
    fitz.PDF_WIDGET_TYPE_BUTTON: "button", fitz.PDF_WIDGET_TYPE_CHECKBOX: "checkbox",
    fitz.PDF_WIDGET_TYPE_COMBOBOX: "combobox", fitz.PDF_WIDGET_TYPE_LISTBOX: "listbox",
    fitz.PDF_WIDGET_TYPE_RADIOBUTTON: "radio", fitz.PDF_WIDGET_TYPE_SIGNATURE: "signature",
    fitz.PDF_WIDGET_TYPE_TEXT: "text",
}


def open_pdf(path: Path):
    try:
        doc = fitz.open(path, filetype="pdf")
    except Exception as e:  # noqa: BLE001
        raise Refuse(f"Could not open {path} as a PDF: {e}")
    return doc


def is_encrypted(doc) -> bool:
    return bool(doc.needs_pass or doc.is_encrypted or (doc.metadata or {}).get("encryption"))


def digital_signatures(doc) -> list[str]:
    """Names/places of existing digital signatures (signed /Sig fields, DocMDP/certification)."""
    found = []
    if doc.needs_pass:
        return found
    for page in doc:
        for w in page.widgets() or []:
            if w.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
                t, v = doc.xref_get_key(w.xref, "V")
                if t != "null":
                    found.append(f"signed field '{w.field_name}' on page {page.number + 1}")
    try:
        flags = doc.get_sigflags()
    except Exception:  # noqa: BLE001
        flags = -1
    t, _ = doc.xref_get_key(doc.pdf_catalog(), "Perms")
    if t != "null":
        found.append("the document has certification permissions (/Perms)")
    return found


@dataclass
class TextLine:
    page: int                 # 1-based
    text: str
    boxes: list               # visual char boxes, one per char of text
    bbox: tuple
    size: float
    baseline: float


@dataclass
class Blank:
    page: int
    x0: float
    x1: float
    y: float                  # visual y of the line itself
    source: str               # underscores / drawn / field
    size: float = DEFAULT_FONT_SIZE
    used: bool = False

    @property
    def length(self):
        return self.x1 - self.x0


@dataclass
class Candidate:
    n: int
    page: int
    kind: str                 # signature / date / name / blank / field
    label: str
    label_bbox: tuple | None
    blank: Blank | None
    score: int
    size: float
    field_rect: tuple | None = None

    def describe(self) -> str:
        where = (f"line x={self.blank.x0:.0f}..{self.blank.x1:.0f} at y={self.blank.y:.0f}"
                 f" ({self.blank.length / PT_PER_IN:.1f} in, {self.blank.source})") if self.blank else "no line found"
        lab = f'"{self.label}" at {fmt_rect(self.label_bbox)}; ' if self.label_bbox else (f'"{self.label}"; ' if self.label else "")
        return f"#{self.n:<3} page {self.page}  {self.kind:<9} {lab}{where}"


SIG_RE = re.compile(r"\b(signature|signed|signer|sign\s+here|sign\s*:)", re.I)
DATE_RE = re.compile(r"\bdated?\b", re.I)
NAME_RE = re.compile(r"\b(print(?:ed)?\s+name|name\s*\(print(?:ed)?\)|full\s+name|name)\b", re.I)
X_RE = re.compile(r"(?:^|\s)(X)\s*_{3,}")
UNDERSCORE_RE = re.compile(r"_{4,}")


def read_page(doc, pno: int):
    """Return (geometry, text lines, blanks, widgets) for one page, all in visual coords.
    Mutates the in-memory page (normalises it) and restores it afterwards."""
    g = page_geometry(doc, pno)
    page = normalise_page(doc, g)
    try:
        lines: list[TextLine] = []
        skipped_vertical = 0
        raw = page.get_text("rawdict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
        for b in raw.get("blocks", []):
            for ln in b.get("lines", []):
                d = ln.get("dir", (1, 0))
                p0 = g.mu_to_vis(0, 0)
                p1 = g.mu_to_vis(d[0], d[1])
                vdx, vdy = p1[0] - p0[0], p1[1] - p0[1]
                if not (vdx > 0.9 and abs(vdy) < 0.1):
                    skipped_vertical += 1
                    continue
                text, boxes, origins, sizes = "", [], [], []
                for sp in ln.get("spans", []):
                    for ch in sp.get("chars", []):
                        text += ch["c"]
                        boxes.append(g.mu_rect_to_vis(ch["bbox"]))
                        origins.append(g.mu_to_vis(*ch["origin"])[1])
                        sizes.append(sp.get("size", DEFAULT_FONT_SIZE))
                if not text.strip():
                    continue
                bbox = (min(b_[0] for b_ in boxes), min(b_[1] for b_ in boxes),
                        max(b_[2] for b_ in boxes), max(b_[3] for b_ in boxes))
                lines.append(TextLine(pno + 1, text, boxes, bbox, max(sizes), sum(origins) / len(origins)))

        blanks: list[Blank] = []
        for tl in lines:
            for m in UNDERSCORE_RE.finditer(tl.text):
                bx = tl.boxes[m.start():m.end()]
                blanks.append(Blank(pno + 1, bx[0][0], bx[-1][2], tl.baseline + 0.18 * tl.size, "underscores", tl.size))
        for path in page.get_drawings():
            for it in path.get("items", []):
                seg = None
                if it[0] == "l":
                    a, c = g.mu_to_vis(it[1].x, it[1].y), g.mu_to_vis(it[2].x, it[2].y)
                    if abs(a[1] - c[1]) < 1.0:
                        seg = (min(a[0], c[0]), max(a[0], c[0]), (a[1] + c[1]) / 2)
                elif it[0] == "re":
                    r = g.mu_rect_to_vis(it[1])
                    if r[3] - r[1] <= 2.5:
                        seg = (r[0], r[2], (r[1] + r[3]) / 2)
                if seg and seg[1] - seg[0] >= 40:
                    blanks.append(Blank(pno + 1, seg[0], seg[1], seg[2], "drawn"))
        blanks = _merge_blanks(blanks)

        widgets = []
        for w in page.widgets() or []:
            widgets.append({
                "page": pno + 1, "name": w.field_name, "type": WIDGET_TYPES.get(w.field_type, str(w.field_type)),
                "rect": g.mu_rect_to_vis(tuple(w.rect)), "value": w.field_value, "xref": w.xref,
                "readonly": bool(w.field_flags & 1),
                "signed": w.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE and doc.xref_get_key(w.xref, "V")[0] != "null",
            })
        return g, lines, blanks, widgets, skipped_vertical
    finally:
        restore_page(doc, g)


def _merge_blanks(blanks):
    out = []
    for b in sorted(blanks, key=lambda b: (b.y, b.x0)):
        for o in out:
            if abs(o.y - b.y) < 2.0 and b.x0 <= o.x1 + 1 and b.x1 >= o.x0 - 1 and (o.source == b.source or True):
                o.x0, o.x1 = min(o.x0, b.x0), max(o.x1, b.x1)
                break
        else:
            out.append(b)
    return out


def _label_box(tl: TextLine, start: int, end: int):
    bx = [b for b, c in zip(tl.boxes[start:end], tl.text[start:end]) if not c.isspace()] or tl.boxes[start:end]
    return (min(b[0] for b in bx), min(b[1] for b in bx), max(b[2] for b in bx), max(b[3] for b in bx))


def _blank_for_label(lb, size, baseline, blanks, row_stop_x):
    """Line belonging to a label: on the same row to its right, else directly above it."""
    best = None
    for b in blanks:
        if abs(b.y - (baseline + 0.18 * size)) <= 0.7 * size and b.x0 >= lb[2] - 2 and b.x0 - lb[2] <= 60 \
                and b.x0 < row_stop_x:
            if best is None or b.x0 < best.x0:
                best = b
    if best:
        return best, "row"
    for b in blanks:
        gap = lb[1] - b.y
        if 0 <= gap <= 2.2 * size + 4 and b.x0 <= lb[2] and b.x1 >= lb[0] and b.length >= 50:
            if best is None or gap < lb[1] - best.y:
                best = b
    return (best, "above") if best else (None, None)


def find_candidates(pages_data) -> list[Candidate]:
    cands: list[Candidate] = []
    for g, lines, blanks, widgets, _ in pages_data:
        page_no = g.pno + 1
        for w in widgets:
            if w["type"] == "signature" and not w["signed"]:
                r = w["rect"]
                cands.append(Candidate(0, page_no, "field", f"signature field '{w['name']}'", None,
                                       Blank(page_no, r[0], r[2], r[3] - 1, "field"), 110,
                                       DEFAULT_FONT_SIZE, field_rect=r))
        for tl in lines:
            labels = []
            for m in SIG_RE.finditer(tl.text):
                labels.append(("signature", m.start(), m.end()))
            for m in DATE_RE.finditer(tl.text):
                labels.append(("date", m.start(), m.end()))
            for m in NAME_RE.finditer(tl.text):
                if not any(s <= m.start() < e for _, s, e in labels):
                    labels.append(("name", m.start(), m.end()))
            for m in X_RE.finditer(tl.text):
                labels.append(("signature-x", m.start(1), m.end(1)))
            labels.sort(key=lambda t: t[1])
            for i, (kind, s, e) in enumerate(labels):
                lb = _label_box(tl, s, e)
                stop = _label_box(tl, labels[i + 1][1], labels[i + 1][2])[0] if i + 1 < len(labels) else 1e9
                blank, how = _blank_for_label(lb, tl.size, tl.baseline, blanks, stop)
                k = "signature" if kind == "signature-x" else kind
                if blank:
                    score = {"row": 100, "above": 90}[how] + (5 if kind == "signature-x" else 0)
                    blank.used = True
                else:
                    score = 30
                cands.append(Candidate(0, page_no, k, tl.text[s:e].strip(), lb, blank, score, tl.size))
        for b in blanks:
            if not b.used and 72 <= b.length <= 450:
                cands.append(Candidate(0, page_no, "blank", "", None, b, 20, b.size))
    cands.sort(key=lambda c: (c.page, round((c.blank.y if c.blank else c.label_bbox[3]) / 3), c.blank.x0 if c.blank else c.label_bbox[0]))
    for i, c in enumerate(cands, 1):
        c.n = i
    return cands


def read_document(doc):
    return [read_page(doc, i) for i in range(len(doc))]


# ---------------------------------------------------------------------------
# Rendering previews
# ---------------------------------------------------------------------------
def _font(size):
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def render_page_png(doc, pno: int, dpi: int, boxes=(), labels=()) -> bytes:
    pix = doc[pno].get_pixmap(dpi=dpi, alpha=False)
    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    s = dpi / 72.0
    if boxes or labels:
        dr = ImageDraw.Draw(img)
        for rect, color in boxes:
            dr.rectangle([rect[0] * s - 3, rect[1] * s - 3, rect[2] * s + 3, rect[3] * s + 3], outline=color, width=2)
        f = _font(max(12, int(11 * s)))
        for (x, y), text, color in labels:
            dr.text((x * s, y * s), text, fill=color, font=f)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def preview_path(stem: str, tag: str, page: int) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", stem)[:60]
    return CACHE_DIR / f"{PREFIX}{safe}-{tag}-p{page}.png"


# ---------------------------------------------------------------------------
# look
# ---------------------------------------------------------------------------
def cmd_look(args) -> int:
    path = check_one_pdf(args.file)
    file_sha = sha256_file(path)
    doc = open_pdf(path)
    print(f"File:      {path}")
    print(f"SHA-256:   {file_sha}")
    if doc.needs_pass:
        print("Encrypted: YES, needs a password. Cannot read it; pdf-sign will not sign it.")
        return 0
    enc = is_encrypted(doc)
    print(f"Encrypted: {'YES (opens without a password, but pdf-sign will not sign it)' if enc else 'no'}")
    sigs = digital_signatures(doc)
    print(f"Digital signature: {'YES - ' + '; '.join(sigs) + '. Ink would break it; pdf-sign will not sign it.' if sigs else 'none'}")
    print(f"Pages:     {len(doc)}")
    data = read_document(doc)
    for g, lines, *_ in data:
        w, h = g.visual_size
        extra = []
        if g.rotation:
            extra.append(f"rotated {g.rotation}")
        if g.crop != g.media:
            extra.append(f"crop box {g.crop} inside media box {g.media}")
        elif g.media[0] or g.media[1]:
            extra.append(f"origin at ({g.media[0]:g},{g.media[1]:g})")
        print(f"  page {g.pno + 1}: {w:.0f} x {h:.0f} pt ({w / 72:.2f} x {h / 72:.2f} in)"
              f"{'  [' + ', '.join(extra) + ']' if extra else ''}{'' if lines else '  [no text layer]'}")
    widgets = [w for *_, ws, _s in data for w in ws]
    if widgets:
        print(f"Form fields: {len(widgets)}")
        for w in widgets:
            val = f" = {w['value']!r}" if w["value"] not in (None, "", "Off") else ""
            flag = " (SIGNED)" if w["signed"] else (" (read-only)" if w["readonly"] else "")
            print(f"  page {w['page']}: {w['type']:<9} '{w['name']}' at {fmt_rect(w['rect'])}{val}{flag}")
    else:
        print("Form fields: none")
    t, v = doc.xref_get_key(doc.pdf_catalog(), "AcroForm")
    acro = doc.xref_object(int(v.split()[0])) if t == "xref" else v
    if "/XFA" in acro:
        print("note: this form has XFA data; some viewers may show a different form.")
    cands = find_candidates(data)
    print("Places that look like signature/date lines (points from top-left of the page as shown):")
    if not cands:
        print("  none found.")
    for c in cands:
        print("  " + c.describe())
    if not any(lines for _, lines, *_ in data):
        print("note: no text layer at all (a scan?). Nothing can be found automatically; "
              "open the previews and use `pdf-sign plan FILE --page N --at X,Y`.")
    vert = sum(d[4] for d in data)
    if vert:
        print(f"note: {vert} text line(s) are not horizontal on the page as shown and were skipped.")
    ensure_private_dir(CACHE_DIR)
    stem = f"{path.stem}-{file_sha[:8]}-look"
    n = min(len(doc), args.max_pages)
    print("Previews (numbers match the list above; blue = signature, green = date, orange = name, grey = other line):")
    colours = {"signature": (30, 90, 230), "field": (30, 90, 230), "date": (20, 150, 60), "name": (230, 130, 0), "blank": (140, 140, 140)}
    for pno in range(n):
        boxes, labels = [], []
        for c in cands:
            if c.page != pno + 1:
                continue
            col = colours[c.kind]
            r = c.field_rect or ((c.blank.x0, c.blank.y - 14, c.blank.x1, c.blank.y + 1) if c.blank else c.label_bbox)
            boxes.append((r, col))
            labels.append(((r[0], r[1] - 16), f"#{c.n}", col))
        out = preview_path(stem, "", pno + 1).with_name(f"{PREFIX}{re.sub(r'[^A-Za-z0-9._-]', '_', stem)[:60]}-p{pno + 1}.png")
        write_private(out, render_page_png(doc, pno, LOOK_DPI, boxes, labels))
        print(f"  {out}")
    if n < len(doc):
        print(f"  (only the first {n} pages; use --max-pages to see more)")
    return 0


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------
def parse_xy(s: str, what: str):
    try:
        x, y = (float(v) for v in s.split(","))
    except ValueError:
        raise Refuse(f"{what} must be X,Y in points from the top-left of the page, e.g. 120,640.")
    return x, y


def parse_date(s: str | None) -> dt.date:
    if not s or s.lower() == "today":
        return dt.date.today()
    for f in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
        try:
            return dt.datetime.strptime(s, f).date()
        except ValueError:
            pass
    raise Refuse(f"Could not read --date '{s}'. Use YYYY-MM-DD or MM/DD/YYYY.")


def text_width(text: str, size: float) -> float:
    return fitz.get_text_length(text, fontname="helv", fontsize=size)


def nearby_size(lines, x, y) -> float | None:
    best, dist = None, 1e9
    for tl in lines:
        cx = min(max(x, tl.bbox[0]), tl.bbox[2])
        d = abs(tl.baseline - y) * 2 + abs(cx - x)
        if d < dist and d < 200:
            best, dist = tl.size, d
    return best


def clamp_size(s):
    return max(7.0, min(14.0, round(s * 2) / 2))


def find_anchor(data, text: str, page: int | None):
    hits = []
    for g, lines, *_ in data:
        if page and g.pno + 1 != page:
            continue
        for tl in lines:
            i = tl.text.lower().find(text.lower())
            if i >= 0:
                hits.append((tl, i, i + len(text)))
    if not hits:
        raise Refuse(f"Anchor text '{text}' not found{' on page ' + str(page) if page else ''}.")
    if len(hits) > 1:
        where = "; ".join(f"page {tl.page} at {fmt_rect(_label_box(tl, s, e))}" for tl, s, e in hits[:8])
        raise Refuse(f"Anchor text '{text}' appears {len(hits)} times ({where}). Add --page N or use longer text.")
    return hits[0]


def place_text_on_blank(blank: Blank, text: str, size: float):
    """Fit text on a line: shrink if it is longer than the line."""
    while size > 7 and text_width(text, size) > blank.length - 4:
        size -= 0.5
    return {"x": round(blank.x0 + 3, 2), "y": round(blank.y - 3, 2), "size": size}


def _row_or_below(cands, kind, page, sig_x1, sig_y):
    """Pick a date/name line near the signature: same row to the right first, then just below."""
    pool = [c for c in cands if c.kind == kind and c.page == page and c.blank]
    row = [c for c in pool if abs(c.blank.y - sig_y) < 20 and c.blank.x0 >= sig_x1 - 30]
    if row:
        return min(row, key=lambda c: c.blank.x0)
    below = [c for c in pool if 0 < c.blank.y - sig_y < 120]
    if below:
        return min(below, key=lambda c: c.blank.y - sig_y)
    above = [c for c in pool if 0 < sig_y - c.blank.y < 60]
    if above:
        return min(above, key=lambda c: sig_y - c.blank.y)
    return None


def build_plan(path: Path, args) -> dict:
    file_sha = sha256_file(path)
    doc = open_pdf(path)
    if is_encrypted(doc):
        raise Refuse("This PDF is encrypted. pdf-sign does not sign encrypted PDFs (it would have to remove "
                     "or rewrite the protection). Ask for an unprotected copy.")
    sigs = digital_signatures(doc)
    if sigs:
        raise Refuse("This PDF already carries a digital signature (" + "; ".join(sigs) + "). Placing ink on it "
                     "would change the file and break that signature. Stopping.")
    data = read_document(doc)
    cands = find_candidates(data)
    sig_img, sig_sha = (load_signature()[:2]) if not args.no_signature else (None, None)
    aspect = sig_img.height / sig_img.width if sig_img else 1.0
    notes = []

    if args.page is not None and not (1 <= args.page <= len(doc)):
        raise Refuse(f"--page {args.page} is out of range (1..{len(doc)}).")

    # ---- fields (--set) ----
    fills = {}
    if args.set:
        widgets = {w["name"]: w for *_, ws, _s in data for w in ws}
        for item in args.set:
            if "=" not in item:
                raise Refuse(f"--set '{item}' must look like name=value.")
            k, v = item.split("=", 1)
            w = widgets.get(k)
            if not w:
                raise Refuse(f"No form field named '{k}'. Fields: {', '.join(sorted(widgets)) or 'none'}.")
            if w["type"] != "text":
                raise Refuse(f"Field '{k}' is a {w['type']} field; --set only fills text fields.")
            if w["readonly"]:
                raise Refuse(f"Field '{k}' is read-only.")
            fills[k] = {"value": v, "page": w["page"], "rect": [round(c, 2) for c in w["rect"]]}

    # ---- signature target ----
    sig = None
    if not args.no_signature:
        blank, label_box, size, field_rect, how = None, None, DEFAULT_FONT_SIZE, None, ""
        page = args.page
        if args.at:
            if page is None:
                if len(doc) > 1:
                    raise Refuse("--at needs --page N on a document with more than one page.")
                page = 1
            x, y = parse_xy(args.at, "--at")
            vw = data[page - 1][0].visual_size[0]
            blank = Blank(page, x, vw - 36, y, "given")
            how = f"--at {x:g},{y:g}"
            size = nearby_size(data[page - 1][1], x, y) or DEFAULT_FONT_SIZE
        elif args.use:
            c = next((c for c in cands if c.n == args.use), None)
            if not c:
                raise Refuse(f"--use {args.use}: no such place. Run `pdf-sign look` to see the numbered list.")
            if c.kind not in ("signature", "field", "blank"):
                raise Refuse(f"--use {args.use} is a {c.kind} place, not a signature place.")
            page, blank, size, field_rect, label_box = c.page, c.blank, c.size, c.field_rect, c.label_bbox
            how = f"place #{c.n} from look"
        elif args.anchor:
            tl, s, e = find_anchor(data, args.anchor, page)
            page = tl.page
            lb = _label_box(tl, s, e)
            blank, _ = _blank_for_label(lb, tl.size, tl.baseline, data[page - 1][2], 1e9)
            size, label_box = tl.size, lb
            if not blank:
                vw = data[page - 1][0].visual_size[0]
                blank = Blank(page, lb[2] + 6, vw - 36, tl.baseline + 1, "after anchor text")
                notes.append("no line next to the anchor; the signature goes right after the anchor text.")
            how = f"anchor '{args.anchor}'"
        else:
            pool = [c for c in cands if c.kind in ("signature", "field") and c.score >= 80
                    and (page is None or c.page == page)]
            if not pool:
                raise Refuse("No clear signature line found" + (f" on page {page}" if page else "") +
                             ". Run `pdf-sign look FILE` and pick a place with --use N, --anchor TEXT or --page N --at X,Y.")
            best = sorted(pool, key=lambda c: (-c.score, c.page, c.blank.y))[0]
            others = [c.n for c in pool if c is not best]
            if others:
                notes.append(f"other signature places exist: {', '.join('#' + str(n) for n in others)} "
                             f"(use --use N to pick one of those instead).")
            page, blank, size, field_rect, label_box = best.page, best.blank, best.size, best.field_rect, best.label_bbox
            how = f"best signature line found (#{best.n})"

        g = data[page - 1][0]
        vw, vh = g.visual_size
        want = (args.sig_width or DEFAULT_SIG_WIDTH_IN) * PT_PER_IN
        room = blank.length - 4
        width = min(want, room)
        if field_rect:
            width = min(width, (field_rect[3] - field_rect[1] - 4) / aspect)
        if width < MIN_SIG_WIDTH_PT:
            raise Refuse(f"The space for the signature is only {room / PT_PER_IN:.2f} in wide; "
                         f"too short for a readable signature. Choose another place.")
        if width < want - 0.5:
            notes.append(f"signature narrowed to {width / PT_PER_IN:.2f} in to fit the line.")
        height = width * aspect
        x0 = blank.x0 + 2
        bottom = blank.y - SIG_GAP_ABOVE_LINE
        # do not run into text printed above the line
        for tl in data[page - 1][1]:
            if label_box and tl.bbox == label_box:
                continue
            if tl.bbox[2] > x0 and tl.bbox[0] < x0 + width and tl.bbox[3] < bottom - 2 and tl.bbox[3] > bottom - height:
                avail = bottom - tl.bbox[3] - 2
                new_w = avail / aspect
                if new_w >= MIN_SIG_WIDTH_PT:
                    width, height = new_w, avail
                    notes.append(f"signature made smaller ({width / PT_PER_IN:.2f} in wide) so it does not touch "
                                 f"the text above: \"{tl.text.strip()[:40]}\".")
                else:
                    notes.append(f"WARNING: the signature may touch the text above: \"{tl.text.strip()[:40]}\".")
        rect = [round(x0, 2), round(bottom - height, 2), round(x0 + width, 2), round(bottom, 2)]
        if rect[0] < 0 or rect[1] < 0 or rect[2] > vw or rect[3] > vh:
            raise Refuse(f"The signature would fall outside page {page} ({fmt_rect(rect)} on a {vw:.0f} x {vh:.0f} page).")
        sig = {"page": page, "rect": rect, "line_y": round(blank.y, 2), "how": how}

    if not sig and not fills:
        raise Refuse("Nothing to do: --no-signature and no --set fields.")

    # ---- date and printed name ----
    def place_extra(kind, text, at, anchor):
        if at:
            x, y = parse_xy(at, f"--{kind}-at")
            pg = args.page or (sig["page"] if sig else 1)
            s = nearby_size(data[pg - 1][1], x, y) or DEFAULT_FONT_SIZE
            return {"page": pg, "text": text, "x": x, "y": y, "size": clamp_size(s), "how": f"--{kind}-at"}
        if anchor:
            tl, s0, e0 = find_anchor(data, anchor, args.page or (sig["page"] if sig else None))
            lb = _label_box(tl, s0, e0)
            b, _ = _blank_for_label(lb, tl.size, tl.baseline, data[tl.page - 1][2], 1e9)
            if not b:
                b = Blank(tl.page, lb[2] + 6, lb[2] + 6 + text_width(text, tl.size) + 10, tl.baseline + 3, "after anchor")
            return {"page": tl.page, "text": text, **place_text_on_blank(b, text, clamp_size(tl.size)), "how": f"anchor '{anchor}'"}
        if not sig:
            return None
        c = _row_or_below(cands, kind, sig["page"], sig["rect"][2], sig["line_y"])
        if c:
            return {"page": c.page, "text": text, **place_text_on_blank(c.blank, text, clamp_size(c.size)),
                    "how": f"{kind} line #{c.n}"}
        lines = data[sig["page"] - 1][1]
        s = clamp_size(nearby_size(lines, sig["rect"][0], sig["line_y"]) or DEFAULT_FONT_SIZE)
        vw = data[sig["page"] - 1][0].visual_size[0]
        if kind == "date" and sig["rect"][2] + 18 + text_width(text, s) < vw - 36:
            return {"page": sig["page"], "text": text, "x": round(sig["rect"][2] + 18, 2), "y": round(sig["line_y"] - 3, 2),
                    "size": s, "how": "no date line found: right of the signature"}
        off = 1.5 if kind == "date" else 1.5 + (1.4 if args.no_date else 2.9)
        return {"page": sig["page"], "text": text, "x": sig["rect"][0], "y": round(sig["line_y"] + s * off, 2),
                "size": s, "how": f"no {kind} line found: under the signature line"}

    date = None
    if not args.no_date:
        d = parse_date(args.date)
        date = place_extra("date", d.strftime(args.date_format or DEFAULT_DATE_FORMAT), args.date_at, args.date_anchor)
        if date is None and not args.no_date and not sig:
            notes.append("no date written (no signature to place it next to; use --date-at to place one).")
    name = None
    if args.name:
        name = place_extra("name", args.name, args.name_at, args.name_anchor)

    for item in (date, name):
        if item:
            g = data[item["page"] - 1][0]
            vw, vh = g.visual_size
            w = text_width(item["text"], item["size"])
            if item["x"] < 0 or item["x"] + w > vw or item["y"] - item["size"] < 0 or item["y"] > vh:
                raise Refuse(f"The text '{item['text']}' would fall outside page {item['page']}.")
            item["rect"] = [round(item["x"], 2), round(item["y"] - item["size"] * 0.8, 2),
                            round(item["x"] + w, 2), round(item["y"] + item["size"] * 0.25, 2)]

    # warn if ink lands on a form field (its appearance may hide it)
    for item, what in ((sig, "signature"), (date, "date"), (name, "name")):
        if not item:
            continue
        r = item["rect"]
        for *_, ws, _s in data:
            for w in ws:
                wr = w["rect"]
                if w["page"] == item["page"] and w["type"] != "signature" and w["name"] not in fills \
                        and r[0] < wr[2] and r[2] > wr[0] and r[1] < wr[3] and r[3] > wr[1]:
                    notes.append(f"WARNING: the {what} overlaps form field '{w['name']}' ({w['type']}); "
                                 f"a viewer may draw the field on top of it." +
                                 (f" Consider --set {w['name']}=... instead." if w["type"] == "text" else ""))

    pages = sorted({i["page"] for i in (sig, date, name) if i} | {f["page"] for f in fills.values()})
    geoms = {p: data[p - 1][0] for p in pages}
    plan = {
        "tool_version": TOOL_VERSION,
        "input_path": str(path),
        "input_sha256": file_sha,
        "signature_sha256": sig_sha if sig else None,
        "page_count": len(doc),
        "pages": {str(p): {"rotation": g.rotation, "media": list(g.media), "crop": list(g.crop)} for p, g in geoms.items()},
        "signature": sig,
        "date": date,
        "name": name,
        "fields": fills,
    }
    plan["id"] = plan_id(plan)
    plan["_notes"] = notes
    return plan


def plan_id(plan: dict) -> str:
    core = {k: v for k, v in plan.items() if k not in ("id", "_notes")}
    return sha256_bytes(json.dumps(core, sort_keys=True, separators=(",", ":")).encode())[:16]


# ---------------------------------------------------------------------------
# Stamping (shared by plan preview and apply, so the preview is exactly what apply does)
# ---------------------------------------------------------------------------
def _img_rot(rotation: int) -> int:
    # The page is normalised (no /Rotate) while we draw, so the image is turned by the page's own
    # rotation; once /Rotate is restored it reads upright. Checked for 0/90/180/270 in the tests.
    return rotation % 360


def _txt_rot(rotation: int) -> int:
    return rotation % 360


def stamp(doc, plan: dict, sig_img: Image.Image | None):
    """Place signature/date/name/fields into the open doc. Returns {page: [visual rects]}."""
    touched: dict[int, list] = {}
    by_page: dict[int, list] = {}
    for key in ("signature", "date", "name"):
        item = plan.get(key)
        if item:
            by_page.setdefault(item["page"], []).append((key, item))
    for p in sorted(by_page):
        g = page_geometry(doc, p - 1)
        exp = plan["pages"][str(p)]
        if [g.rotation, list(g.media), list(g.crop)] != [exp["rotation"], exp["media"], exp["crop"]]:
            raise Refuse(f"Page {p} geometry differs from the plan; refusing.")
        page = normalise_page(doc, g)
        try:
            for key, item in by_page[p]:
                if key == "signature":
                    r = item["rect"]
                    mu = g.vis_rect_to_mu(r)
                    page.insert_image(mu, stream=signature_png_for(sig_img, r[2] - r[0]),
                                      keep_proportion=False, rotate=_img_rot(g.rotation), overlay=True)
                else:
                    pt = fitz.Point(*g.vis_to_mu(item["x"], item["y"]))
                    page.insert_text(pt, item["text"], fontsize=item["size"], fontname="helv",
                                     color=(0, 0, 0), rotate=_txt_rot(g.rotation))
                touched.setdefault(p, []).append(item["rect"])
        finally:
            restore_page(doc, g)
    for name, f in (plan.get("fields") or {}).items():
        page = doc[f["page"] - 1]
        for w in page.widgets() or []:
            if w.field_name == name:
                w.field_value = f["value"]
                w.update()
                break
        else:
            raise Refuse(f"Field '{name}' disappeared; refusing.")
        touched.setdefault(f["page"], []).append(f["rect"])
    return touched


def changed_box(before: bytes, after: bytes, size, dpi):
    """Bounding box (visual points) of pixels that differ between two RGB renders."""
    from PIL import ImageChops
    a = Image.frombytes("RGB", size, before)
    b = Image.frombytes("RGB", size, after)
    diff = ImageChops.difference(a, b).convert("L").point(lambda v: 255 if v > 24 else 0)
    box = diff.getbbox()
    if not box:
        return None
    s = 72.0 / dpi
    return (box[0] * s, box[1] * s, box[2] * s, box[3] * s)


def verify_stamp(orig_doc, new_doc, touched: dict, dpi=72):
    """Render each touched page before and after; every changed pixel must be inside the planned boxes."""
    for p, rects in touched.items():
        a = orig_doc[p - 1].get_pixmap(dpi=dpi, alpha=False)
        b = new_doc[p - 1].get_pixmap(dpi=dpi, alpha=False)
        if (a.width, a.height) != (b.width, b.height):
            raise Refuse(f"Page {p} changed size while stamping; refusing.")
        box = changed_box(a.samples, b.samples, (a.width, a.height), dpi)
        if box is None:
            raise Refuse(f"Nothing visible changed on page {p}; refusing (the stamp did not land).")
        t = VERIFY_TOLERANCE_PT + 72.0 / dpi
        ux0 = min(r[0] for r in rects) - t
        uy0 = min(r[1] for r in rects) - t
        ux1 = max(r[2] for r in rects) + t
        uy1 = max(r[3] for r in rects) + t
        if box[0] < ux0 or box[1] < uy0 or box[2] > ux1 or box[3] > uy1:
            raise Refuse(f"Self-check failed on page {p}: ink landed at {fmt_rect(box)} but the plan said "
                         f"{fmt_rect((ux0 + t, uy0 + t, ux1 - t, uy1 - t))}. Nothing was written.")


def cmd_plan(args) -> int:
    path = check_one_pdf(args.file)
    plan = build_plan(path, args)
    pid = plan["id"]
    sig_img = load_signature()[0] if plan["signature"] else None
    data = path.read_bytes()
    orig = fitz.open(stream=data, filetype="pdf")
    work = fitz.open(stream=data, filetype="pdf")
    touched = stamp(work, plan, sig_img)
    verify_stamp(orig, work, touched)
    ensure_private_dir(CACHE_DIR)
    ensure_private_dir(PLAN_DIR)
    notes = plan.pop("_notes")
    write_private(PLAN_DIR / f"{PREFIX}{pid}.json", json.dumps(plan, indent=2, sort_keys=True).encode())
    print(f"PLAN {pid}   (nothing has been signed)")
    print(f"File:      {path}")
    print(f"SHA-256:   {plan['input_sha256']}")
    s = plan["signature"]
    if s:
        r = s["rect"]
        print(f"Signature: page {s['page']}, {(r[2] - r[0]) / 72:.2f} x {(r[3] - r[1]) / 72:.2f} in, "
              f"left edge x={r[0]:.0f}, bottom y={r[3]:.0f} (line at y={s['line_y']:.0f})  [{s['how']}]")
    else:
        print("Signature: none (--no-signature)")
    for key in ("date", "name"):
        it = plan[key]
        if it:
            print(f"{key.capitalize() + ':':<10} '{it['text']}' page {it['page']}, x={it['x']:.0f}, baseline y={it['y']:.0f}, "
                  f"{it['size']:g} pt Helvetica  [{it['how']}]")
        elif key == "date":
            print("Date:      none" + (" (--no-date)" if args.no_date else ""))
    for k, f in plan["fields"].items():
        print(f"Field:     '{k}' = {f['value']!r} (page {f['page']})")
    for n in notes:
        print(f"note: {n}")
    print("Preview (red boxes mark what will be added; the boxes themselves are not added):")
    stem = f"{path.stem}-{pid}-plan"
    for p in sorted(touched):
        out = CACHE_DIR / f"{PREFIX}{re.sub(r'[^A-Za-z0-9._-]', '_', stem)[:60]}-p{p}.png"
        write_private(out, render_page_png(work, p - 1, PLAN_DPI, [(r, (220, 0, 0)) for r in touched[p]]))
        print(f"  {out}")
    print("Show the signer the preview. Only after they say yes for this document:")
    print(f"  pdf-sign apply {path} --plan {pid} --yes-signer-said \"<the signer's exact words>\"")
    return 0


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------
def cmd_apply(args) -> int:
    path = check_one_pdf(args.file)
    words = (args.yes_signer_said or "").strip()
    if not words:
        raise Refuse("--yes-signer-said is missing or empty. Apply only runs with the signer's own words saying yes for this document.")
    if not args.plan or not re.fullmatch(r"[0-9a-f]{16}", args.plan):
        raise Refuse("--plan must be the 16-character plan id printed by `pdf-sign plan`.")
    pf = PLAN_DIR / f"{PREFIX}{args.plan}.json"
    if not pf.is_file():
        raise Refuse(f"No saved plan {args.plan} (plans expire after a day). Run `pdf-sign plan` again and show the signer the preview.")
    plan = json.loads(pf.read_text())
    if plan_id(plan) != args.plan or plan.get("id") != args.plan:
        raise Refuse("The saved plan does not match its id (placement changed). Run `pdf-sign plan` again.")
    if plan["input_path"] != str(path):
        raise Refuse(f"Plan {args.plan} was made for {plan['input_path']}, not {path}.")
    data = path.read_bytes()
    in_sha = sha256_bytes(data)
    if in_sha != plan["input_sha256"]:
        raise Refuse("The file has changed since the plan was made (SHA-256 differs). Run `pdf-sign plan` again "
                     "and show the signer the new preview.")
    orig = fitz.open(stream=data, filetype="pdf")
    if is_encrypted(orig):
        raise Refuse("This PDF is encrypted. pdf-sign does not sign encrypted PDFs.")
    sigs = digital_signatures(orig)
    if sigs:
        raise Refuse("This PDF already carries a digital signature (" + "; ".join(sigs) + "). Ink would break it. Stopping.")
    if len(orig) != plan["page_count"]:
        raise Refuse("Page count differs from the plan; refusing.")
    sig_img = None
    if plan["signature"]:
        sig_img, sig_sha, _ = load_signature()
        if sig_sha != plan["signature_sha256"]:
            raise Refuse("The signature image changed since the plan was made. Run `pdf-sign plan` again.")

    out = Path(args.out).expanduser().resolve() if args.out else path.with_name(path.stem + ".signed.pdf")
    if out.suffix.lower() != ".pdf":
        raise Refuse("--out must end in .pdf.")
    if out == path:
        raise Refuse("The output cannot be the input file; the input is never overwritten.")
    if out.exists() or out.is_symlink():
        raise Refuse(f"{out} already exists. pdf-sign never overwrites; move it away or give --out.")
    if not out.parent.is_dir():
        raise Refuse(f"Folder {out.parent} does not exist.")

    tmp = out.with_name(f".{out.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        doc = fitz.open(tmp)
        touched = stamp(doc, plan, sig_img)
        verify_stamp(orig, doc, touched)
        if doc.can_save_incrementally():
            doc.save(doc.name, incremental=True, encryption=fitz.PDF_ENCRYPT_KEEP, deflate=True, deflate_images=True)  # original bytes stay untouched at the front
            doc.close()
        else:
            tmp2 = tmp.with_name(tmp.name + "2")
            doc.save(tmp2, garbage=0, deflate=True)
            doc.close()
            os.replace(tmp2, tmp)
        os.chmod(tmp, 0o600)
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        # final check of the written file
        chk = fitz.open(tmp)
        verify_stamp(orig, chk, touched)
        chk.close()
        try:
            os.link(tmp, out)   # fails if out appeared meanwhile: never overwrite
        except FileExistsError:
            raise Refuse(f"{out} appeared while signing; not overwriting.")
    finally:
        if tmp.exists():
            tmp.unlink()
    os.chmod(out, 0o600)
    out_sha = sha256_file(out)
    if sha256_file(path) != in_sha:
        print("WARNING: the input file changed during apply (not by pdf-sign).", file=sys.stderr)

    ensure_private_dir(STATE_DIR)
    s = plan["signature"]
    rec = {
        "time": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "plan": args.plan, "input": str(path), "input_sha256": in_sha,
        "output": str(out), "output_sha256": out_sha,
        "page": s["page"] if s else None, "signature_rect": s["rect"] if s else None,
        "date": plan["date"]["text"] if plan["date"] else None,
        "date_page": plan["date"]["page"] if plan["date"] else None,
        "date_xy": [plan["date"]["x"], plan["date"]["y"]] if plan["date"] else None,
        "name": plan["name"]["text"] if plan["name"] else None,
        "fields": {k: v["value"] for k, v in plan["fields"].items()},
        "signer_said": words,
    }
    fd = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(rec) + "\n")
    os.chmod(LOG_FILE, 0o600)

    print(f"Signed copy: {out}  (mode 600)")
    print(f"SHA-256:     {out_sha}")
    print(f"Input left unchanged: {path} (SHA-256 {in_sha[:16]}...)")
    if s:
        print(f"Signature on page {s['page']} at {fmt_rect(s['rect'])}" +
              (f"; date '{plan['date']['text']}'" if plan["date"] else "; no date"))
    print(f"Logged to {LOG_FILE}")
    ensure_private_dir(CACHE_DIR)
    res = fitz.open(out)
    for p in sorted(touched):
        pv = CACHE_DIR / f"{PREFIX}{re.sub(r'[^A-Za-z0-9._-]', '_', out.stem)[:60]}-{args.plan}-signed-p{p}.png"
        write_private(pv, render_page_png(res, p - 1, PLAN_DPI))
        print(f"Signed page preview: {pv}")
    return 0


# ---------------------------------------------------------------------------
# fields (list text fields; filling goes through plan --set / apply)
# ---------------------------------------------------------------------------
def cmd_fields(args) -> int:
    path = check_one_pdf(args.file)
    doc = open_pdf(path)
    if doc.needs_pass:
        raise Refuse("This PDF needs a password.")
    ws = [w for *_, wl, _s in read_document(doc) for w in wl]
    if not ws:
        print("No form fields.")
        return 0
    for w in ws:
        fill = "fillable with --set" if w["type"] == "text" and not w["readonly"] else "not fillable by pdf-sign"
        print(f"page {w['page']}: {w['type']:<9} '{w['name']}' value={w['value']!r}  [{fill}]")
    if args.set:
        print("\nTo fill: pdf-sign plan FILE --set name=value [--no-signature] ... then apply as usual.")
    return 0


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------
def cmd_clean(args) -> int:
    now = time.time()
    victims = []
    for d in (CACHE_DIR, PLAN_DIR):
        if not d.is_dir():
            continue
        for e in os.scandir(d):
            if not e.name.startswith(PREFIX) or not (e.name.endswith(".png") or e.name.endswith(".json")):
                continue
            st = e.stat(follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                continue
            if now - st.st_mtime > CLEAN_AGE_SECONDS:
                victims.append(Path(d, e.name))
    if not victims:
        print(f"Nothing older than a day in {CACHE_DIR}.")
        return 0
    print(f"{'Would remove' if args.dry_run else 'Removing'} {len(victims)} file(s) older than a day:")
    for v in victims:
        print(f"  {v}")
    if not args.dry_run:
        for v in victims:
            os.unlink(v)
        print("Done.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
HELP = """\
Put the signer's handwritten signature and the date on ONE PDF, the way you would sign
a printed form. This is ink on the page, not a digital certificate.

The rule: sign one named document at a time, only when the signer says so for that
document, and show him the preview BEFORE signing. So the steps are:

  1. pdf-sign look  FILE.pdf          see what is in it and where it could be signed
  2. pdf-sign plan  FILE.pdf [...]    work out the spot, make a preview PNG, get a plan id
  3. show the signer the preview; they say yes
  4. pdf-sign apply FILE.pdf --plan ID --yes-signer-said "<their words>"

The input file is never changed. The signed copy is written next to it as
NAME.signed.pdf. Coordinates are points (1/72 inch) from the top-left corner
of the page as it is shown, the same as in the preview pictures.
"""


def build_parser():
    ap = argparse.ArgumentParser(prog="pdf-sign", description=HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    p = sub.add_parser("look", help="read-only: pages, fields, protection, likely signature/date lines, preview PNGs",
                       description="Read-only. Shows pages, sizes, form fields, encryption and digital signatures, and "
                                   "every place that looks like a signature or date line, numbered. Writes page "
                                   "previews with those places marked.")
    p.add_argument("file", help="one PDF file")
    p.add_argument("--max-pages", type=int, default=40, help="preview at most this many pages (default 40)")
    p.set_defaults(func=cmd_look)

    p = sub.add_parser("plan", help="read-only: decide where signature and date go, write a preview, print a plan id",
                       description="Read-only. Decides where the signature (and date, and optional printed name) "
                                   "will go, draws them into a preview PNG exactly as they will appear, and prints a "
                                   "plan id. Nothing is signed. By default it uses the best signature line found.")
    p.add_argument("file", help="one PDF file")
    w = p.add_argument_group("where the signature goes (pick at most one way; default: best line found)")
    w.add_argument("--use", type=int, metavar="N", help="use place #N from `pdf-sign look`")
    w.add_argument("--anchor", metavar="TEXT", help="use the line next to (or above) this text, e.g. 'Tenant signature'")
    w.add_argument("--at", metavar="X,Y", help="left end of the line at X, the line itself at Y (needs --page on multi-page files)")
    w.add_argument("--page", type=int, metavar="N", help="only look on page N (1 = first page)")
    w.add_argument("--sig-width", type=float, metavar="INCHES", help="signature width (default 2; never wider than the line)")
    w.add_argument("--no-signature", action="store_true", help="no signature (only with --set, to fill fields)")
    d = p.add_argument_group("date")
    d.add_argument("--no-date", action="store_true", help="do not write a date")
    d.add_argument("--date", metavar="DATE", help="date to write: YYYY-MM-DD or MM/DD/YYYY (default today)")
    d.add_argument("--date-format", metavar="FMT", help="strftime format (default %%m/%%d/%%Y, like 11/22/2026)")
    d.add_argument("--date-at", metavar="X,Y", help="put the date's text start at X, baseline at Y")
    d.add_argument("--date-anchor", metavar="TEXT", help="put the date on the line next to this text")
    n = p.add_argument_group("printed name (optional)")
    n.add_argument("--name", metavar="TEXT", help="also print this name")
    n.add_argument("--name-at", metavar="X,Y", help="where the name goes (text start X, baseline Y)")
    n.add_argument("--name-anchor", metavar="TEXT", help="put the name on the line next to this text")
    f = p.add_argument_group("form fields")
    f.add_argument("--set", action="append", metavar="NAME=VALUE", help="fill a text field (repeat for more)")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("apply", help="sign exactly as a plan showed, after the signer said yes",
                       description="Places the signature and date exactly as the plan's preview showed. Refuses if "
                                   "the file changed since the plan, if the signer's words are missing, if the output exists, "
                                   "or if the PDF is encrypted or already digitally signed. Never overwrites the input.")
    p.add_argument("file", help="the same PDF the plan was made for")
    p.add_argument("--plan", required=True, metavar="ID", help="plan id printed by `pdf-sign plan`")
    p.add_argument("--yes-signer-said", required=True, metavar="WORDS", help="the signer's own words saying yes for this document")
    p.add_argument("--out", metavar="FILE.pdf", help="where to write the signed copy (default NAME.signed.pdf next to it)")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("fields", help="list form fields and which can be filled (fill with plan --set)",
                       description="Lists form fields. Text fields can be filled through the normal path: "
                                   "pdf-sign plan FILE --set name=value [--no-signature], then apply.")
    p.add_argument("file", help="one PDF file")
    p.add_argument("--set", action="append", metavar="NAME=VALUE", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_fields)

    p = sub.add_parser("clean", help="delete this tool's previews and plans older than a day (lists them first)",
                       description=f"Lists, then deletes, preview PNGs and saved plans older than a day in {CACHE_DIR}. "
                                   f"Only files this tool made (names starting '{PREFIX}').")
    p.add_argument("--dry-run", action="store_true", help="only list, delete nothing")
    p.set_defaults(func=cmd_clean)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "plan":
        ways = [x for x in (args.use, args.anchor, args.at) if x]
        if len(ways) > 1:
            print("pdf-sign: refused: choose only one of --use, --anchor, --at.", file=sys.stderr)
            return 2
    try:
        return args.func(args)
    except Refuse as e:
        print(f"pdf-sign: refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
