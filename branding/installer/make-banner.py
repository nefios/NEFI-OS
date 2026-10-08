#!/usr/bin/env python3
"""NEFI OS - banner per le schermate del Debian Installer, a qualsiasi dimensione.
Uso: python3 make-banner.py <sfondo-installer.jpg> <larghezza> <altezza> <output.png>"""
import sys
from PIL import Image, ImageDraw

SRC, BW, BH, OUT = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
BG_DEEP, BG_DARK, LIME = (1, 15, 0), (5, 31, 4), (125, 186, 82)
src = Image.open(SRC).convert("RGB")
W, H = src.size
BOX = (int(W * 286 / 1112), int(H * 28 / 944), int(W * 821 / 1112), int(H * 194 / 944))
banner = Image.new("RGB", (BW, BH), BG_DEEP)
px = banner.load()
for x in range(BW):
    t = 1 - abs(x - BW / 2) / (BW / 2)
    col = tuple(int(BG_DEEP[i] + (BG_DARK[i] * 2.2 - BG_DEEP[i]) * t) for i in range(3))
    for y in range(BH):
        px[x, y] = col
logo = src.crop(BOX)
lp = logo.load()
ix0, iy0 = int(W * 22 / 1112), int(H * 22 / 944)
ix1, iy1 = logo.width - ix0, logo.height - int(H * 12 / 944)
for x in range(ix0, ix1):
    for y in range(iy0, iy1):
        r, g, b = lp[x, y]
        if max(r, g, b) < 150 and not (g > 150 and g - r > 40 and g - b > 60):
            lp[x, y] = BG_DARK
margin = max(3, BH // 12)
lh = BH - 2 * margin - 2
lw = int(logo.width * lh / logo.height)
if lw > BW - 20:
    lw = BW - 20
    lh = int(logo.height * lw / logo.width)
logo = logo.resize((lw, lh), Image.LANCZOS)
banner.paste(logo, ((BW - lw) // 2, (BH - 2 - lh) // 2))
ImageDraw.Draw(banner).line([(0, BH - 2), (BW, BH - 2)], fill=LIME, width=2)
banner.save(OUT, optimize=True)
print(f"banner {BW}x{BH} -> {OUT}")
