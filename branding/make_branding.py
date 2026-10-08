#!/usr/bin/env python3
"""NEFI OS — genera tutti gli asset grafici a partire dai loghi originali."""
import os, sys, glob, json
from PIL import Image, ImageDraw, ImageFilter

HOME = os.path.expanduser("~")
OUT = os.environ.get("NEFI_OUT", os.path.join(HOME, "nefi-os/config/includes.chroot"))
SRC_DIRS = [os.environ.get("NEFI_SRC", ""), f"{HOME}/Downloads", f"{HOME}/Scaricati", f"{HOME}/downloads"]

def find(*names):
    for d in SRC_DIRS:
        if not d:
            continue
        for n in names:
            for p in glob.glob(os.path.join(d, n)):
                return p
    sys.exit(f"ERRORE: non trovo {names[0]} in ~/Downloads")

color_logo = find("nefipng.png")
white_logo = find("logo_bianco.png", "logo bianco.png")
full_logo  = find("logo nefi.png", "logo_nefi.png")
print("Sorgenti:\n ", color_logo, "\n ", white_logo, "\n ", full_logo)

def square_crop(path):
    im = Image.open(path).convert("RGBA")
    l, t, r, b = im.getchannel("A").getbbox()
    side = max(r - l, b - t)
    pad = int(side * 0.06)
    sq = Image.new("RGBA", (side + 2 * pad,) * 2, (0, 0, 0, 0))
    sq.paste(im.crop((l, t, r, b)), (pad + (side - (r - l)) // 2, pad + (side - (b - t)) // 2))
    return sq

def save(img, rel):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    img.save(p)
    return p

# ── 1. Icone (logo a colori) ────────────────────────────
icon = square_crop(color_logo)
white_icon = square_crop(white_logo)
for s in (16, 22, 24, 32, 48, 64, 128, 256):
    save(icon.resize((s, s), Image.LANCZOS), f"usr/share/icons/hicolor/{s}x{s}/apps/nefi-os.png")
    save(white_icon.resize((s, s), Image.LANCZOS), f"usr/share/icons/hicolor/{s}x{s}/apps/nefi-security-center.png")
save(icon.resize((256, 256), Image.LANCZOS), "usr/share/pixmaps/nefi-os.png")
save(icon.resize((256, 256), Image.LANCZOS), "usr/share/nefi/logo-color.png")
print("✓ Icone generate (16-256 px)")

# ── 2. Logo bianco per NEFI Security Center ─────────────
white = square_crop(white_logo)
save(white.resize((128, 128), Image.LANCZOS), "usr/share/nefi/logo-white.png")
print("✓ Logo bianco per il Security Center")

# ── 3. Sfondo desktop in più risoluzioni ────────────────
src = Image.open(full_logo).convert("RGB")

def wallpaper(W, H):
    # sfondo: l'originale stirato a tutto schermo e sfocato -> stessi colori del logo
    bg = src.resize((W, H), Image.LANCZOS).filter(ImageFilter.GaussianBlur(H // 10))
    # logo originale scalato all'altezza, con bordi sfumati per fondersi senza stacchi
    scale = H / src.height
    lw = int(src.width * scale)
    logo = src.resize((lw, H), Image.LANCZOS)
    mask = Image.new("L", (lw, H), 0)
    ImageDraw.Draw(mask).ellipse((lw * 0.13, H * -0.05, lw * 0.87, H * 1.05), fill=255)
    mask = mask.filter(ImageFilter.GaussianBlur(H // 10))
    bg.paste(logo, ((W - lw) // 2, 0), mask)
    return bg

for W, H in ((1920, 1080), (2560, 1440), (3840, 2160)):
    save(wallpaper(W, H), f"usr/share/wallpapers/NEFI/contents/images/{W}x{H}.png")
save(src, "usr/share/nefi/logo-full.png")

meta = {"KPlugin": {"Id": "NEFI", "Name": "NEFI OS",
        "Authors": [{"Name": "NEFI OS Project"}], "License": "CC-BY-SA-4.0"}}
p = os.path.join(OUT, "usr/share/wallpapers/NEFI/metadata.json")
with open(p, "w") as f:
    json.dump(meta, f, indent=2)
print("✓ Sfondi 1920x1080, 2560x1440, 3840x2160")
print("FATTO — asset grafici generati in", OUT)
