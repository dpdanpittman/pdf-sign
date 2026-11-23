"""Make sample PDFs and a FAKE scribble signature for tests. Never touches the real signature."""
import io
import math
import os

import pymupdf as fitz
from PIL import Image, ImageDraw


def fake_signature(path):
    img = Image.new("RGBA", (1200, 240), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pts = [(40 + i * 8, 140 + 60 * math.sin(i / 4.0) * (1 if i % 17 else -0.5)) for i in range(140)]
    d.line(pts, fill=(10, 20, 120, 255), width=9)
    d.line([(60, 200), (1100, 190)], fill=(10, 20, 120, 255), width=6)
    img.save(path, "PNG")
    os.chmod(path, 0o600)
    return path


def simple_form(path):
    doc = fitz.open()
    p = doc.new_page(width=612, height=792)
    p.insert_text((72, 90), "Permission Slip", fontsize=18)
    p.insert_text((72, 130), "I agree to the terms described above.", fontsize=11)
    p.insert_text((72, 300), "Signature: ______________________________   Date: ______________", fontsize=11)
    doc.save(path)
    return path


def contract(path):
    doc = fitz.open()
    p = doc.new_page()
    p.insert_text((72, 90), "SERVICES AGREEMENT", fontsize=16)
    for i in range(20):
        p.insert_text((72, 130 + i * 16), f"Clause {i + 1}. The parties agree to the clause number {i + 1}.", fontsize=10)
    p2 = doc.new_page()
    p2.insert_text((72, 90), "IN WITNESS WHEREOF the parties sign below.", fontsize=10)
    p2.draw_line((72, 400), (300, 400))
    p2.insert_text((72, 414), "Client Signature", fontsize=10)
    p2.draw_line((340, 400), (500, 400))
    p2.insert_text((340, 414), "Date", fontsize=10)
    doc.save(path)
    return path


def fillable(path):
    doc = fitz.open()
    p = doc.new_page()
    p.insert_text((72, 100), "Full name:", fontsize=11)
    w = fitz.Widget()
    w.field_name = "full_name"
    w.field_type = fitz.PDF_WIDGET_TYPE_TEXT
    w.rect = fitz.Rect(150, 86, 400, 104)
    p.add_widget(w)
    p.insert_text((72, 300), "Signature:", fontsize=11)
    s = fitz.Widget()
    s.field_name = "sig1"
    s.field_type = fitz.PDF_WIDGET_TYPE_SIGNATURE
    s.rect = fitz.Rect(150, 260, 400, 305)
    p.add_widget(s)
    doc.save(path)
    return path


def rotated(path, rot=90):
    doc = fitz.open()
    p = doc.new_page(width=612, height=792)
    p.set_rotation(rot)
    # write text so it reads upright on the page as displayed
    g = p.derotation_matrix
    pt = fitz.Point(72, 300) * g
    p.insert_text(pt, "Signature: ______________________________  Date: ____________", fontsize=11, rotate=rot)
    doc.save(path)
    return path


def shifted_crop(path):
    doc = fitz.open()
    p = doc.new_page(width=612, height=792)
    p.insert_text((100, 400), "Signature: ______________________________  Date: ____________", fontsize=11)
    p.set_cropbox(fitz.Rect(50, 100, 580, 700))
    doc.save(path)
    return path


def rotated_and_cropped(path):
    doc = fitz.open()
    p = doc.new_page(width=612, height=792)
    p.set_cropbox(fitz.Rect(50, 100, 580, 700))
    p.set_rotation(180)
    pt = fitz.Point(100, 400) * p.derotation_matrix
    p.insert_text(pt, "Signature: ______________________________  Date: ____________", fontsize=11, rotate=180)
    doc.save(path)
    return path


def nonzero_origin(path):
    """MediaBox that does not start at 0,0 (written by hand)."""
    simple_form(path + ".src")
    doc = fitz.open(path + ".src")
    doc.xref_set_key(doc[0].xref, "MediaBox", "[-100 -50 512 742]")
    doc.save(path)
    os.unlink(path + ".src")
    return path


def encrypted(path):
    src = simple_form(path + ".src")
    doc = fitz.open(src)
    doc.save(path, encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="user")
    os.unlink(src)
    return path


def encrypted_no_user_pw(path):
    src = simple_form(path + ".src")
    doc = fitz.open(src)
    doc.save(path, encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="",
             permissions=fitz.PDF_PERM_PRINT)
    os.unlink(src)
    return path


def digitally_signed(path):
    """A form whose signature field has a /V signature dictionary (looks signed to readers)."""
    fillable(path + ".src")
    doc = fitz.open(path + ".src")
    sigx = doc.get_new_xref()
    doc.update_object(sigx, "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached "
                            "/ByteRange [0 0 0 0] /Contents <00> >>")
    for w in doc[0].widgets():
        if w.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
            doc.xref_set_key(w.xref, "V", f"{sigx} 0 R")
    doc.save(path)
    os.unlink(path + ".src")
    return path


def scanned(path):
    """Image-only page (no text layer)."""
    img = Image.new("RGB", (850, 1100), "white")
    d = ImageDraw.Draw(img)
    d.text((100, 400), "Signature: ________________", fill="black")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    doc = fitz.open()
    p = doc.new_page()
    p.insert_image(p.rect, stream=buf.getvalue())
    doc.save(path)
    return path
