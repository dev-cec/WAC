#!/usr/bin/env python3
"""retitle-cover.py — derives a cover page with another title from a WAC cover.

The covers (`cover_FR.png`, `cover_EN.png`) are raster images: their text can
only be repainted. Every WAC document shares the same cover; only the large
blue title ("Documentation") changes from one document to another — e.g. the
testing guide. This script erases that title and draws the new one in the same
place, colour and cap height, so that all covers keep one layout.

How it stays faithful to the original (same method as translate-cover.py):
  - the font was identified by overlaying candidates on the original glyphs:
    Figtree, weight 600, sized so that its cap height matches the original
    (the closest of fifteen geometric sans-serifs compared);
  - the colour is sampled from the darkest quarter of the title's pixels,
    before erasing;
  - erasing interpolates the background row by row between the pixels just
    left and right of the block, which preserves the page's gradients.

Font (SIL Open Font License), downloaded next to this script or passed with
--fonts:
  https://github.com/google/fonts/raw/main/ofl/figtree/Figtree%5Bwght%5D.ttf

Usage:
  python3 retitle-cover.py --title "Guide des tests" cover_FR.png cover_tests_FR.png
  python3 retitle-cover.py --title "Testing guide"   cover_EN.png cover_tests_EN.png
"""
import argparse
import os
import statistics
import sys

from PIL import Image, ImageDraw, ImageFont

# The title block, measured on both covers (pixels of the 1024 x 1536 image).
TITLE = (73, 316, 602, 373)
# Right edge of the free band the new title may extend into: the page's
# decoration starts beyond it.
RIGHT_LIMIT = 980
WEIGHT = 600


def figtree(path, size):
    f = ImageFont.truetype(path, size)
    f.set_variation_by_axes([WEIGHT])
    return f


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fonts", default=here)
    ap.add_argument("--title", required=True, help="the new title")
    ap.add_argument("source")
    ap.add_argument("output")
    a = ap.parse_args()
    path = os.path.join(a.fonts, "Figtree[wght].ttf")
    if not os.path.exists(path):
        sys.exit(f"missing font: {path} (see the header of this script)")

    im = Image.open(a.source).convert("RGB")
    px = im.load()
    x0, y0, x1, y1 = TITLE

    # Colour of the original title, before it is erased.
    ink = [px[x, y] for y in range(y0, y1 + 1) for x in range(x0, x1 + 1)
           if sum(px[x, y]) / 3 < 200]
    if not ink:
        sys.exit("no title found in the expected block: is this a WAC cover?")
    ink.sort(key=sum)
    ink = ink[:max(1, len(ink) // 4)]
    colour = tuple(int(statistics.median(c[i] for c in ink)) for i in range(3))

    # Erase: each row interpolated between the pixels just outside the block.
    m = 6
    for y in range(y0 - m, y1 + m + 1):
        left, right = px[x0 - m - 2, y], px[x1 + m + 2, y]
        for x in range(x0 - m, x1 + m + 1):
            t = (x - (x0 - m)) / ((x1 + m) - (x0 - m))
            px[x, y] = tuple(int(left[i] * (1 - t) + right[i] * t) for i in range(3))

    # Size: the cap height of the original ("D", top at y0, baseline at y1).
    cap = y1 - y0 + 1
    size = 10.0
    while figtree(path, size + 0.1).getbbox("H")[3] - figtree(path, size + 0.1).getbbox("H")[1] <= cap:
        size += 0.1
    f = figtree(path, size)
    bbox = f.getbbox(a.title)
    if x0 + bbox[2] - bbox[0] > RIGHT_LIMIT:
        sys.exit(f"title too long for the cover: {a.title!r}")
    top = f.getbbox("H")[1]
    ImageDraw.Draw(im).text((x0 - bbox[0], y0 - top), a.title, font=f, fill=colour)

    im.save(a.output)
    print(f"written: {a.output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")
