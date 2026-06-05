"""Generate AegisEDR logo PNG and ICO using Pillow only (no cairosvg needed)."""
from PIL import Image, ImageDraw, ImageFont
import os, math, io

OUT = os.path.dirname(__file__)

def shield_points(cx, cy, w, h):
    """Returns polygon points for a shield shape."""
    hw = w / 2
    return [
        (cx - hw * 0.85, cy - h * 0.50),   # top-left
        (cx + hw * 0.85, cy - h * 0.50),   # top-right
        (cx + hw,        cy - h * 0.15),   # right shoulder
        (cx + hw,        cy + h * 0.15),   # right mid
        (cx + hw * 0.45, cy + h * 0.50),   # right bottom
        (cx,             cy + h * 0.62),   # bottom tip
        (cx - hw * 0.45, cy + h * 0.50),   # left bottom
        (cx - hw,        cy + h * 0.15),   # left mid
        (cx - hw,        cy - h * 0.15),   # left shoulder
    ]

def lerp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))

def draw_shield(draw: ImageDraw.ImageDraw, cx, cy, w, h, scale=1):
    pts = shield_points(cx, cy, w, h)
    c1, c2 = (99, 102, 241), (168, 85, 247)

    # Gradient simulation: draw filled bands
    steps = max(int(h * scale), 60)
    for i in range(steps):
        t  = i / steps
        y  = cy - h * 0.5 + h * t
        c  = lerp_color(c1, c2, t)

        # Clip to shield shape on each scanline
        xs = []
        for j in range(len(pts)):
            p1, p2 = pts[j], pts[(j + 1) % len(pts)]
            if min(p1[1], p2[1]) <= y <= max(p1[1], p2[1]):
                if p2[1] != p1[1]:
                    x = p1[0] + (p2[0] - p1[0]) * (y - p1[1]) / (p2[1] - p1[1])
                    xs.append(x)
        if len(xs) >= 2:
            xs.sort()
            draw.line([(int(xs[0]), int(y)), (int(xs[-1]), int(y))], fill=c + (255,), width=1)

    # Border
    draw.polygon(pts, outline=(255, 255, 255, 60))

# ── ICON (256×256) ─────────────────────────────────────────────────────────
def make_icon(size=256) -> Image.Image:
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    scale = size / 256

    cx, cy = size // 2, size // 2
    sw, sh = int(200 * scale), int(220 * scale)

    draw_shield(draw, cx, cy, sw, sh, scale)

    # Inner "A"
    font_size = int(120 * scale)
    try:
        font = ImageFont.truetype("arialbd.ttf", font_size)
    except Exception:
        try:
            font = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", font_size)
        except Exception:
            font = ImageFont.load_default()

    # Shadow
    draw.text((cx - font_size//4 + 2, cy - font_size//2 + 2), "A",
              font=font, fill=(0, 0, 0, 80), anchor="mm" if hasattr(font, 'getbbox') else None)
    # Letter
    draw.text((cx - font_size//4, cy - font_size//2), "A",
              font=font, fill=(255, 255, 255, 245), anchor="mm" if hasattr(font, 'getbbox') else None)

    # Crossbar on A
    bar_y = cy - int(5 * scale)
    bar_w = int(65 * scale)
    bar_h = int(8 * scale)
    draw.rounded_rectangle(
        [cx - bar_w, bar_y, cx + bar_w, bar_y + bar_h],
        radius=bar_h // 2, fill=(255, 255, 255, 200)
    )
    return img

# ── LOGO (520×160) ─────────────────────────────────────────────────────────
def make_logo() -> Image.Image:
    W, H = 520, 160
    img  = Image.new("RGBA", (W, H), (13, 15, 20, 255))
    draw = ImageDraw.Draw(img)

    # Shield on left
    cx, cy = 80, 82
    draw_shield(draw, cx, cy, 110, 128)

    # "AEGIS" text
    try:
        font_big = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 52)
        font_tag = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 13)
    except Exception:
        font_big = ImageFont.load_default()
        font_tag = font_big

    # AEGIS (white)
    draw.text((160, 22), "AEGIS", font=font_big, fill=(226, 232, 240, 255))
    # EDR (purple)
    aegis_w = draw.textlength("AEGIS", font=font_big) if hasattr(draw, 'textlength') else 160
    draw.text((160 + aegis_w, 22), "EDR", font=font_big, fill=(129, 140, 248, 255))

    # Tagline
    draw.text((163, 112), "ENDPOINT  DETECTION  &  RESPONSE",
              font=font_tag, fill=(100, 116, 139, 255))

    # Divider line
    draw.rectangle([160, 107, 490, 108], fill=(42, 47, 62, 255))

    # Inner A on shield
    try:
        font_a = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 72)
    except Exception:
        font_a = ImageFont.load_default()

    draw.text((cx - 20, cy - 42), "A", font=font_a, fill=(255, 255, 255, 230))
    draw.rounded_rectangle([cx - 30, cy + 12, cx + 30, cy + 20], radius=4, fill=(255, 255, 255, 190))

    return img

# ── Generate files ─────────────────────────────────────────────────────────
print("Generating AegisEDR assets...")

# icon.png (256×256)
icon256 = make_icon(256)
icon256.save(os.path.join(OUT, "icon.png"))
print("  [OK] icon.png  (256x256)")

# icon.ico (multi-size)
icons = []
for s in [16, 24, 32, 48, 64, 128, 256]:
    icons.append(make_icon(s).convert("RGBA"))

icons[0].save(
    os.path.join(OUT, "icon.ico"),
    format="ICO",
    sizes=[(s, s) for s in [16, 24, 32, 48, 64, 128, 256]],
    append_images=icons[1:]
)
print("  [OK] icon.ico  (16/24/32/48/64/128/256)")

# logo.png (520×160)
logo = make_logo()
logo.save(os.path.join(OUT, "logo.png"))
print("  [OK] logo.png  (520x160)")

# logo_wizard.bmp (164×314 for Inno Setup wizard side image)
wiz = Image.new("RGB", (164, 314), (13, 15, 20))
icon_scaled = make_icon(120)
wiz.paste(icon_scaled, ((164-120)//2, 60), icon_scaled)
try:
    font_wiz = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 18)
    font_sub = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 10)
    d = ImageDraw.Draw(wiz)
    d.text((82, 196), "AEGIS", font=font_wiz, fill=(226, 232, 240), anchor="mm")
    d.text((82, 218), "EDR", font=font_wiz, fill=(129, 140, 248), anchor="mm")
    d.text((82, 242), "Endpoint Security", font=font_sub, fill=(100, 116, 139), anchor="mm")
except Exception:
    pass
wiz.save(os.path.join(OUT, "logo_wizard.bmp"))
print("  [OK] logo_wizard.bmp (164x314)")

# logo_header.bmp (55×55 for Inno Setup header)
hdr = Image.new("RGB", (55, 55), (13, 15, 20))
icon_hdr = make_icon(48).convert("RGBA")
bg = Image.new("RGB", (48, 48), (13, 15, 20))
bg.paste(icon_hdr, (0, 0), icon_hdr)
hdr.paste(bg, (3, 3))
hdr.save(os.path.join(OUT, "logo_header.bmp"))
print("  [OK] logo_header.bmp (55x55)")

print(f"\n[DONE] All assets saved to: {OUT}")
