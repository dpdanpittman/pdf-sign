"""Offline tests for pdf-sign. They use a FAKE scribble signature via $PDF_SIGN_SIGNATURE,
and private temp folders for cache/state, so the real signature and the user's files are never touched."""
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

import pymupdf as fitz
import pytest
from PIL import Image

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "pdf_sign.py"
sys.path.insert(0, str(HERE))
import samples  # noqa: E402

REAL_SIG = Path.home() / ".config/pdf-sign/signature.png"


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


@pytest.fixture()
def env(tmp_path):
    fake = samples.fake_signature(str(tmp_path / "fake-sig.png"))
    e = dict(os.environ, PDF_SIGN_SIGNATURE=fake, PDF_SIGN_CACHE=str(tmp_path / "cache"),
             PDF_SIGN_STATE=str(tmp_path / "state"))
    assert Path(fake).resolve() != REAL_SIG.resolve()

    class E:
        dir = tmp_path
        vars = e
        cache = tmp_path / "cache"
        state = tmp_path / "state"
        sig = Path(fake)

        def run(self, *args, ok=True):
            r = subprocess.run([sys.executable, "-I", str(TOOL), *map(str, args)], env=self.vars,
                               capture_output=True, text=True, timeout=120)
            if ok is True:
                assert r.returncode == 0, r.stdout + r.stderr
            elif ok is False:
                assert r.returncode != 0, r.stdout + r.stderr
            return r

        def plan(self, pdf, *opts):
            r = self.run("plan", pdf, *opts)
            m = re.search(r"^PLAN ([0-9a-f]{16})", r.stdout, re.M)
            assert m, r.stdout
            return m.group(1), r

        def make(self, name, maker=None, *a):
            p = str(self.dir / f"{name}.pdf")
            (maker or getattr(samples, name))(p, *a)
            return Path(p)

    return E()


def plan_json(env, pid):
    return json.loads((env.cache / "plans" / f"pdfsign-{pid}.json").read_text())


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def preview_paths(out):
    return [Path(l.strip()) for l in out.splitlines() if l.strip().endswith(".png")]


# ---------------------------------------------------------------- look
def test_look_simple_form(env):
    pdf = env.make("simple_form")
    r = env.run("look", pdf)
    assert "Pages:     1" in r.stdout
    assert re.search(r"#1\s+page 1\s+signature\s+\"Signature\"", r.stdout)
    assert re.search(r"#2\s+page 1\s+date\s+\"Date\"", r.stdout)
    assert "Encrypted: no" in r.stdout and "Digital signature: none" in r.stdout
    pv = preview_paths(r.stdout)
    assert len(pv) == 1 and pv[0].exists() and mode(pv[0]) == 0o600
    assert mode(env.cache) == 0o700


def test_look_contract_finds_page_2(env):
    pdf = env.make("contract")
    r = env.run("look", pdf)
    assert re.search(r"page 2\s+signature", r.stdout)
    assert not re.search(r"page 1\s+signature", r.stdout)
    assert len(preview_paths(r.stdout)) == 2


def test_look_fillable_lists_fields(env):
    r = env.run("look", env.make("fillable"))
    assert "text      'full_name'" in r.stdout
    assert "signature 'sig1'" in r.stdout
    assert "field     \"signature field 'sig1'\"" in r.stdout


def test_look_rotated_and_crop(env):
    r = env.run("look", env.make("rot90", samples.rotated, 90))
    assert "rotated 90" in r.stdout and "792 x 612" in r.stdout and "signature" in r.stdout
    r = env.run("look", env.make("shifted_crop"))
    assert "crop box" in r.stdout and "530 x 600" in r.stdout


def test_look_encrypted_and_signed(env):
    r = env.run("look", env.make("encrypted"))
    assert "needs a password" in r.stdout
    r = env.run("look", env.make("encrypted_no_user_pw"))
    assert "Encrypted: YES" in r.stdout
    r = env.run("look", env.make("digitally_signed"))
    assert "Digital signature: YES" in r.stdout and "(SIGNED)" in r.stdout


def test_look_scanned(env):
    r = env.run("look", env.make("scanned"))
    assert "no text layer" in r.stdout and "none found" in r.stdout


def test_one_file_only(env):
    env.make("simple_form")
    env.run("look", env.dir / "*.pdf", ok=False)
    r = env.run("look", env.dir, ok=False)
    assert "folder" in r.stderr
    env.run("look", env.dir / "nope.pdf", ok=False)


# ---------------------------------------------------------------- plan + apply on every sample
CASES = [
    ("simple_form", samples.simple_form, ()),
    ("contract", samples.contract, ()),
    ("fillable", samples.fillable, ()),
    ("rot90", samples.rotated, (90,)),
    ("rot180", samples.rotated, (180,)),
    ("rot270", samples.rotated, (270,)),
    ("shifted_crop", samples.shifted_crop, ()),
    ("rotated_and_cropped", samples.rotated_and_cropped, ()),
    ("nonzero_origin", samples.nonzero_origin, ()),
]


@pytest.mark.parametrize("name,maker,a", CASES, ids=[c[0] for c in CASES])
def test_plan_and_apply(env, name, maker, a):
    pdf = env.make(name, maker, *a)
    before = sha(pdf)
    pid, r = env.plan(pdf)
    assert "nothing has been signed" in r.stdout
    pv = preview_paths(r.stdout)
    assert pv and all(p.exists() and mode(p) == 0o600 for p in pv)
    assert not (pdf.parent / f"{pdf.stem}.signed.pdf").exists()
    assert sha(pdf) == before
    plan = plan_json(env, pid)

    r = env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "yes, sign the test form")
    out = pdf.parent / f"{pdf.stem}.signed.pdf"
    assert out.exists() and mode(out) == 0o600
    assert sha(pdf) == before, "input must never change"
    # original bytes are kept unchanged at the front (incremental update)
    assert out.read_bytes()[: pdf.stat().st_size] == pdf.read_bytes()
    assert out.stat().st_size - pdf.stat().st_size < 150_000, "file bloated"

    doc = fitz.open(out)
    src = fitz.open(pdf)
    s = plan["signature"]
    page = doc[s["page"] - 1]
    # text stays selectable; date is real text
    assert src[s["page"] - 1].get_text().strip() in page.get_text() or "Signature" in page.get_text() or name == "fillable"
    assert plan["date"]["text"] in page.get_text()
    # one image embedded once
    imgs = page.get_images(full=True)
    assert len(imgs) == 1
    # the page is not rasterised: no image covers the whole page
    assert imgs[0][2] < 2000
    # geometry intact
    assert page.rect == src[s["page"] - 1].rect and page.rotation == src[s["page"] - 1].rotation
    # signature sits on the line: bottom a little above it
    assert 0 < s["line_y"] - s["rect"][3] <= 3
    # width ~2 in unless the line is shorter
    assert (s["rect"][2] - s["rect"][0]) <= 2 * 72 + 0.01
    # ink is inside the planned box on the rendered page
    pix = page.get_pixmap(dpi=72, alpha=False)
    pix0 = src[s["page"] - 1].get_pixmap(dpi=72, alpha=False)
    a_ = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    b_ = Image.frombytes("RGB", (pix0.width, pix0.height), pix0.samples)
    from PIL import ImageChops
    box = ImageChops.difference(a_, b_).convert("L").point(lambda v: 255 if v > 24 else 0).getbbox()
    rects = [s["rect"], plan["date"]["rect"]]
    assert box[0] >= min(r[0] for r in rects) - 5 and box[2] <= max(r[2] for r in rects) + 5
    assert box[1] >= min(r[1] for r in rects) - 5 and box[3] <= max(r[3] for r in rects) + 5
    # log line
    rec = json.loads((env.state / "log.jsonl").read_text().splitlines()[-1])
    assert rec["input_sha256"] == before and rec["output_sha256"] == sha(out)
    assert rec["signer_said"] == "yes, sign the test form" and rec["page"] == s["page"]
    assert len(json.dumps(rec)) < 2000
    assert mode(env.state / "log.jsonl") == 0o600 and mode(env.state) == 0o700

    # second apply to the same output refuses, and nothing changes
    out_sha = sha(out)
    r = env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "yes again", ok=False)
    assert "already exists" in r.stderr
    assert sha(out) == out_sha and sha(pdf) == before


def test_fillable_fields_survive(env):
    pdf = env.make("fillable")
    pid, _ = env.plan(pdf)
    env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "ok")
    doc = fitz.open(pdf.parent / "fillable.signed.pdf")
    names = {w.field_name: w.field_type for w in doc[0].widgets()}
    assert names == {"full_name": fitz.PDF_WIDGET_TYPE_TEXT, "sig1": fitz.PDF_WIDGET_TYPE_SIGNATURE}
    plan = plan_json(env, pid)
    assert "sig1" in plan["signature"]["how"] or "#" in plan["signature"]["how"]
    r = plan["signature"]["rect"]
    assert 150 <= r[0] and r[2] <= 400 and 260 <= r[1] and r[3] <= 305   # inside the field


@pytest.mark.parametrize("rot", [0, 90, 180, 270])
@pytest.mark.parametrize("crop", [False, True])
def test_orientation_upright(env, rot, crop):
    """A two-colour test image must read left=red, right=green on the page as shown."""
    img = Image.new("RGBA", (600, 120), (0, 0, 0, 0))
    for x in range(600):
        for y in range(20, 100):
            img.putpixel((x, y), (255, 0, 0, 255) if x < 300 else (0, 200, 0, 255))
    img.save(env.sig)
    os.chmod(env.sig, 0o600)
    doc = fitz.open()
    p = doc.new_page(width=612, height=792)
    if crop:
        p.set_cropbox(fitz.Rect(40, 60, 560, 760))
    p.set_rotation(rot)
    pdf = env.dir / f"o{rot}{crop}.pdf"
    doc.save(pdf)
    pid, _ = env.plan(pdf, "--at", "100,300", "--no-date")
    env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "ok")
    r = plan_json(env, pid)["signature"]["rect"]
    out = fitz.open(pdf.parent / f"{pdf.stem}.signed.pdf")
    pix = out[0].get_pixmap(dpi=72, alpha=False)
    im = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    cy = int((r[1] + r[3]) / 2)
    left = im.getpixel((int(r[0] + (r[2] - r[0]) * 0.25), cy))
    right = im.getpixel((int(r[0] + (r[2] - r[0]) * 0.75), cy))
    assert left[0] > 200 and left[1] < 80, left
    assert right[1] > 150 and right[0] < 80, right


# ---------------------------------------------------------------- refusals
def test_refuse_missing_or_empty_words(env):
    pdf = env.make("simple_form")
    pid, _ = env.plan(pdf)
    r = env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "", ok=False)
    assert "missing or empty" in r.stderr
    env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "   ", ok=False)
    env.run("apply", pdf, "--plan", pid, ok=False)
    assert not (env.dir / "simple_form.signed.pdf").exists()


def test_refuse_after_file_changed(env):
    pdf = env.make("simple_form")
    pid, _ = env.plan(pdf)
    doc = fitz.open(pdf)
    doc[0].insert_text((72, 500), "a sneaky new clause", fontsize=11)
    doc.save(str(pdf) + ".new")
    os.replace(str(pdf) + ".new", pdf)
    r = env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "yes", ok=False)
    assert "changed since the plan" in r.stderr
    assert not (env.dir / "simple_form.signed.pdf").exists()


def test_refuse_tampered_plan(env):
    pdf = env.make("simple_form")
    pid, _ = env.plan(pdf)
    pf = env.cache / "plans" / f"pdfsign-{pid}.json"
    plan = json.loads(pf.read_text())
    plan["signature"]["rect"][1] -= 100
    pf.write_text(json.dumps(plan))
    r = env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "yes", ok=False)
    assert "does not match its id" in r.stderr


def test_refuse_unknown_plan_and_other_file(env):
    pdf = env.make("simple_form")
    r = env.run("apply", pdf, "--plan", "0123456789abcdef", "--yes-signer-said", "yes", ok=False)
    assert "No saved plan" in r.stderr
    pid, _ = env.plan(pdf)
    other = env.dir / "copy.pdf"
    other.write_bytes(pdf.read_bytes())
    r = env.run("apply", other, "--plan", pid, "--yes-signer-said", "yes", ok=False)
    assert "was made for" in r.stderr


def test_refuse_out_is_input(env):
    pdf = env.make("simple_form")
    pid, _ = env.plan(pdf)
    r = env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "yes", "--out", pdf, ok=False)
    assert "cannot be the input" in r.stderr


def _forge_plan(env, pdf, base_pdf):
    """Make a valid plan for base_pdf, then re-point it at pdf with pdf's real sha (tests apply's own checks)."""
    sys.path.insert(0, str(TOOL.parent))
    import pdf_sign
    pid, _ = env.plan(base_pdf)
    plan = plan_json(env, pid)
    plan["input_path"] = str(Path(pdf).resolve())
    plan["input_sha256"] = sha(pdf)
    plan.pop("id")
    plan["id"] = pdf_sign.plan_id(plan)
    (env.cache / "plans" / f"pdfsign-{plan['id']}.json").write_text(json.dumps(plan))
    return plan["id"]


def test_refuse_encrypted(env):
    enc = env.make("encrypted_no_user_pw")
    r = env.run("plan", enc, ok=False)
    assert "encrypted" in r.stderr
    pid = _forge_plan(env, enc, env.make("simple_form"))
    r = env.run("apply", enc, "--plan", pid, "--yes-signer-said", "yes", ok=False)
    assert "encrypted" in r.stderr
    env.run("plan", env.make("encrypted"), ok=False)


def test_refuse_digitally_signed(env):
    ds = env.make("digitally_signed")
    r = env.run("plan", ds, ok=False)
    assert "digital signature" in r.stderr and "break" in r.stderr
    pid = _forge_plan(env, ds, env.make("fillable"))
    r = env.run("apply", ds, "--plan", pid, "--yes-signer-said", "yes", ok=False)
    assert "digital signature" in r.stderr
    assert not (env.dir / "digitally_signed.signed.pdf").exists()


def test_refuse_bad_signature_file(env):
    pdf = env.make("simple_form")
    os.chmod(env.sig, 0o644)
    r = env.run("plan", pdf, ok=False)
    assert "permissions" in r.stderr
    env.vars["PDF_SIGN_SIGNATURE"] = str(env.dir / "missing.png")
    r = env.run("plan", pdf, ok=False)
    assert "not found" in r.stderr


def test_refuse_signature_changed_between_plan_and_apply(env):
    pdf = env.make("simple_form")
    pid, _ = env.plan(pdf)
    Image.new("RGBA", (300, 60), (0, 0, 0, 0)).save(env.sig)
    img = Image.open(env.sig)
    img.putpixel((10, 10), (0, 0, 0, 255))
    img.save(env.sig)
    os.chmod(env.sig, 0o600)
    r = env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "yes", ok=False)
    assert "signature image changed" in r.stderr


def test_scanned_needs_explicit_spot(env):
    pdf = env.make("scanned")
    r = env.run("plan", pdf, ok=False)
    assert "No clear signature line" in r.stderr
    pid, r = env.plan(pdf, "--at", "120,500")
    assert "--at 120,500" in r.stdout


# ---------------------------------------------------------------- options
def test_options_use_anchor_date_name(env):
    pdf = env.make("contract")
    pid, r = env.plan(pdf, "--anchor", "Client Signature", "--date", "2026-12-01", "--name", "Alex Example")
    plan = plan_json(env, pid)
    assert plan["date"]["text"] == "12/01/2026" and plan["name"]["text"] == "Alex Example"
    assert plan["signature"]["page"] == 2
    pid2, _ = env.plan(pdf, "--use", "1", "--no-date", "--sig-width", "1.5")
    p2 = plan_json(env, pid2)
    assert p2["date"] is None and abs((p2["signature"]["rect"][2] - p2["signature"]["rect"][0]) - 108) < 0.1
    pid3, _ = env.plan(pdf, "--use", "1", "--date-format", "%Y-%m-%d", "--date", "11/22/2026")
    assert plan_json(env, pid3)["date"]["text"] == "2026-11-22"
    assert len({pid, pid2, pid3}) == 3
    env.run("plan", pdf, "--use", "2", ok=False)          # #2 is a date place
    env.run("plan", pdf, "--at", "100,100", ok=False)     # multi-page needs --page
    env.run("plan", pdf, "--use", "1", "--at", "1,1", ok=False)


def test_sig_never_wider_than_line(env):
    doc = fitz.open()
    p = doc.new_page()
    p.insert_text((72, 300), "Signature: ____________________", fontsize=11)
    pdf = env.dir / "short.pdf"
    doc.save(pdf)
    pid, r = env.plan(pdf)
    s = plan_json(env, pid)["signature"]
    assert s["rect"][2] - s["rect"][0] < 2 * 72
    assert "narrowed" in r.stdout


def test_plan_id_stable_and_changes_with_placement(env):
    pdf = env.make("simple_form")
    a, _ = env.plan(pdf, "--date", "2026-11-22")
    b, _ = env.plan(pdf, "--date", "2026-11-22")
    c, _ = env.plan(pdf, "--date", "2026-11-23")
    assert a == b != c


def test_fields_fill(env):
    pdf = env.make("fillable")
    r = env.run("fields", pdf)
    assert "'full_name'" in r.stdout and "fillable with --set" in r.stdout
    pid, r = env.plan(pdf, "--set", "full_name=Alex Example", "--no-signature", "--no-date")
    env.run("apply", pdf, "--plan", pid, "--yes-signer-said", "fill it")
    doc = fitz.open(env.dir / "fillable.signed.pdf")
    vals = {w.field_name: w.field_value for w in doc[0].widgets()}
    assert vals["full_name"] == "Alex Example"
    env.run("plan", pdf, "--set", "nope=1", ok=False)
    env.run("plan", pdf, "--set", "sig1=1", ok=False)


# ---------------------------------------------------------------- clean
def test_clean(env):
    env.run("look", env.make("simple_form"))
    env.cache.mkdir(exist_ok=True)
    old = env.cache / "pdfsign-old-look-p1.png"
    old.write_bytes(b"x")
    stranger = env.cache / "someone-else.png"
    stranger.write_bytes(b"x")
    t = time.time() - 3 * 86400
    os.utime(old, (t, t))
    os.utime(stranger, (t, t))
    r = env.run("clean", "--dry-run")
    assert str(old) in r.stdout and old.exists()
    r = env.run("clean")
    assert str(old) in r.stdout and not old.exists()
    assert stranger.exists()
    assert any(p.name.startswith("pdfsign-simple_form") for p in env.cache.iterdir())  # fresh preview kept


def test_help_plain(env):
    r = env.run("--help")
    assert "show him the preview" in r.stdout
    for sub in ("look", "plan", "apply", "fields", "clean"):
        env.run(sub, "--help")
