#!/usr/bin/env python3
"""translate-cover.py — builds the English cover page from the French one.

The French cover (`page de garde.png`) is a raster image: its text cannot be
edited, only repainted. This script erases each French text block and redraws
the English text in the same fonts, sizes, colours and positions, so both
covers share one layout and stay in step.

How it stays faithful to the original:
  - fonts were identified by overlaying candidates on the original glyphs and
    calibrating each size on the measured width of the French line: Nunito Sans
    (weight 450) for the publisher line and the subtitle, Montserrat Medium for
    the letter-spaced capitals at the bottom;
  - colours are sampled from the darkest quarter of each block's text pixels,
    before erasing;
  - erasing interpolates the background row by row between the pixels just left
    and right of the block, which preserves the page's gradients;
  - the CEC emblem is left untouched: it is an official badge, its lettering is
    part of the drawing.

Fonts (SIL Open Font License), downloaded next to this script or passed with
--fonts:
  https://github.com/google/fonts/raw/main/ofl/montserrat/Montserrat%5Bwght%5D.ttf
  https://github.com/google/fonts/raw/main/ofl/nunitosans/NunitoSans%5BYTLC%2Copsz%2Cwdth%2Cwght%5D.ttf

Usage:
  python3 translate-cover.py [--fonts DIR] ["page de garde.png"] ["cover page.png"]
"""
import argparse
import os
import statistics
import sys

from PIL import Image, ImageDraw, ImageFont


def font(path, size, axes):
    f = ImageFont.truetype(path, size)
    f.set_variation_by_axes(axes)
    return f


def fitted_size(path, axes, text, width, tracking_em=0.0):
    """Size at which `text` spans `width` pixels, letter spacing included."""
    best = None
    for tenth in range(80, 900):
        size = tenth / 10
        f = font(path, size, axes)
        w = f.getlength(text) + tracking_em * size * (len(text) - 1)
        if best is None or abs(w - width) < best[0]:
            best = (abs(w - width), size)
    return best[1]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fonts", default=here)
    ap.add_argument("source", nargs="?", default=os.path.join(here, "page de garde.png"))
    ap.add_argument("output", nargs="?", default=os.path.join(here, "cover page.png"))
    a = ap.parse_args()
    montserrat = os.path.join(a.fonts, "Montserrat[wght].ttf")
    nunito = os.path.join(a.fonts, "NunitoSans[YTLC,opsz,wdth,wght].ttf")
    for f in (montserrat, nunito):
        if not os.path.exists(f):
            sys.exit(f"missing font: {f} (see the header of this script)")

    im = Image.open(a.source).convert("RGB")
    px = im.load()

    def colour(box):
        x0, y0, x1, y1 = box
        ink = [px[x, y] for y in range(y0, y1) for x in range(x0, x1) if sum(px[x, y]) / 3 < 200]
        ink.sort(key=sum)
        ink = ink[:max(1, len(ink) // 4)]
        return tuple(int(statistics.median(c[i] for c in ink)) for i in range(3))

    def erase(box, margin=4):
        x0, y0, x1, y1 = box
        x0 -= margin; y0 -= margin; x1 += margin; y1 += margin
        for y in range(y0, y1 + 1):
            left, right = px[x0 - 2, y], px[x1 + 2, y]
            for x in range(x0, x1 + 1):
                t = (x - x0) / (x1 - x0)
                px[x, y] = tuple(int(left[i] * (1 - t) + right[i] * t) for i in range(3))

    def write(draw, x, cap_top, text, f, fill, tracking=0.0):
        """Draws `text` with its capital-letter top at `cap_top`."""
        top = f.getbbox("H")[1]
        xx = x - f.getbbox(text[0])[0]
        for ch in text:
            draw.text((xx, cap_top - top), ch, font=f, fill=fill)
            xx += f.getlength(ch) + tracking

    # Blocks measured on the French cover (pixels of the 1024 x 1536 image).
    publisher, subtitle = (70, 258, 651, 275), (74, 571, 893, 656)
    labels = [(70, 1397, 169, 1428), (227, 1397, 335, 1428), (381, 1397, 489, 1429)]
    motto = (603, 1341, 796, 1395)

    c_publisher, c_subtitle = colour(publisher), colour(subtitle)
    c_labels, c_motto = colour((70, 1397, 489, 1429)), colour(motto)
    for box in [publisher, subtitle] + labels + [motto]:
        erase(box)

    draw = ImageDraw.Draw(im)
    nunito_axes = [450, 100, 12, 500]          # weight, width, optical size, YTLC

    # Publisher line: size fitted on the French line, with the same tracking.
    size = fitted_size(nunito, nunito_axes,
                       "Créé par le Centre d’Excellence Cyberdéfense Aérospatiale (CEC)", 581, 0.04)
    write(draw, 70, 261, "Created by the Aerospace Cyber Defence Centre of Excellence (CEC)",
          font(nunito, size, nunito_axes), c_publisher, 0.04 * size)

    size = fitted_size(nunito, nunito_axes, "Logiciel de prélèvement d’artefacts Windows", 819)
    f = font(nunito, size, nunito_axes)
    write(draw, 74, 574, "Windows artefact collection software", f, c_subtitle)
    write(draw, 74, 622, "for digital forensic investigation", f, c_subtitle)

    f = font(montserrat, 14.5, [500])
    for x, (l1, l2) in [(70, ("SYSTEM", "ARTEFACTS")), (227, ("USER", "FILES")),
                        (381, ("DIGITAL", "EVIDENCE"))]:
        write(draw, x, 1397, l1, f, c_labels, 0.16 * 14.5)
        write(draw, x, 1418, l2, f, c_labels, 0.16 * 14.5)

    f = font(montserrat, 14.3, [500])
    for y, text in [(1341, "A TOOL IN SUPPORT"), (1362, "OF DIGITAL"), (1383, "INVESTIGATION")]:
        write(draw, 603, y, text, f, c_motto, 0.16 * 14.3)

    im.save(a.output)
    print(f"written: {a.output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")
