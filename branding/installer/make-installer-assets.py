#!/usr/bin/env python3
"""NEFI OS - immagini dell'installer da sfondo-installer.jpg.
Uso: python3 make-installer-assets.py <sfondo-installer.jpg> <cartella-output>"""
import sys, os
from PIL import Image, ImageFilter

SRC, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
src = Image.open(SRC).convert("RGB")
W, H = src.size


def fit_canvas(size):
    cw, ch = size
    scale = min(cw / W, ch / H)
    fw, fh = int(W * scale), int(H * scale)
    front = src.resize((fw, fh), Image.LANCZOS)
    edge = front.crop((0, 0, 6, fh)).resize((1, fh), Image.BOX)
    edge2 = front.crop((fw - 6, 0, fw, fh)).resize((1, fh), Image.BOX)
    col = Image.blend(edge, edge2, 0.5).filter(ImageFilter.GaussianBlur(6))
    back = col.resize((cw, fh), Image.NEAREST)
    if fh != ch:
        back = back.resize((cw, ch), Image.LANCZOS)
    feather = max(8, fw // 7)
    ramp = Image.new("L", (fw, 1), 255)
    for x in range(feather):
        v = int(255 * (x / feather) ** 1.5)
        ramp.putpixel((x, 0), v)
        ramp.putpixel((fw - 1 - x, 0), v)
    mask = ramp.resize((fw, fh), Image.NEAREST)
    back.paste(front, ((cw - fw) // 2, (ch - fh) // 2), mask)
    return back


fit_canvas((640, 480)).save(os.path.join(OUT, "splash-640x480.png"), optimize=True)
fit_canvas((1024, 768)).save(os.path.join(OUT, "bg-1024x768.png"), optimize=True)
fit_canvas((1920, 1080)).save(os.path.join(OUT, "bg-1920x1080.png"), optimize=True)
print("FATTO - immagini create in", OUT)
