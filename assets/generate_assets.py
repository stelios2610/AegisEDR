"""
Generate PNG and ICO files from SVG logos.
Requirements: pip install cairosvg Pillow
"""
import os
import sys

ASSETS_DIR = os.path.dirname(__file__)

def generate():
    try:
        import cairosvg
        from PIL import Image
        import io
    except ImportError:
        print("Installing dependencies...")
        os.system(f"{sys.executable} -m pip install cairosvg Pillow")
        import cairosvg
        from PIL import Image
        import io

    # logo.svg → logo.png (full size)
    cairosvg.svg2png(
        url=os.path.join(ASSETS_DIR, "logo.svg"),
        write_to=os.path.join(ASSETS_DIR, "logo.png"),
        output_width=520, output_height=160
    )
    print("✓ logo.png")

    # logo.svg → logo_installer.bmp (164x314 for Inno Setup wizard image)
    cairosvg.svg2png(
        url=os.path.join(ASSETS_DIR, "logo.svg"),
        write_to=os.path.join(ASSETS_DIR, "logo_wizard.png"),
        output_width=164, output_height=314
    )
    img = Image.open(os.path.join(ASSETS_DIR, "logo_wizard.png"))
    # White background for BMP
    bg = Image.new("RGB", img.size, (13, 15, 20))
    bg.paste(img, mask=img.split()[3] if img.mode == 'RGBA' else None)
    bg.save(os.path.join(ASSETS_DIR, "logo_wizard.bmp"))
    print("✓ logo_wizard.bmp (Inno Setup wizard image)")

    # logo_header.bmp (55x55 for Inno Setup header)
    cairosvg.svg2png(
        url=os.path.join(ASSETS_DIR, "logo.svg"),
        write_to=os.path.join(ASSETS_DIR, "logo_header_tmp.png"),
        output_width=55, output_height=55
    )
    img = Image.open(os.path.join(ASSETS_DIR, "logo_header_tmp.png"))
    bg = Image.new("RGB", img.size, (13, 15, 20))
    bg.paste(img, mask=img.split()[3] if img.mode == 'RGBA' else None)
    bg.save(os.path.join(ASSETS_DIR, "logo_header.bmp"))
    os.remove(os.path.join(ASSETS_DIR, "logo_header_tmp.png"))
    print("✓ logo_header.bmp (Inno Setup header image)")

    # icon.svg → icon.ico (multi-size)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    icons = []
    for size in sizes:
        png_data = cairosvg.svg2png(
            url=os.path.join(ASSETS_DIR, "icon.svg"),
            output_width=size, output_height=size
        )
        icons.append(Image.open(io.BytesIO(png_data)).convert("RGBA"))

    icons[0].save(
        os.path.join(ASSETS_DIR, "icon.ico"),
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=icons[1:]
    )
    print("✓ icon.ico (multi-size: 16,24,32,48,64,128,256)")

    # icon.png (256x256)
    cairosvg.svg2png(
        url=os.path.join(ASSETS_DIR, "icon.svg"),
        write_to=os.path.join(ASSETS_DIR, "icon.png"),
        output_width=256, output_height=256
    )
    print("✓ icon.png")

    print("\n✓ All assets generated in:", ASSETS_DIR)

if __name__ == "__main__":
    generate()
