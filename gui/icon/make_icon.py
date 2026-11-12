#!/usr/bin/env python3
"""Draw the loom-desk app icon (a small weave on a dark rounded square) as a 1024x1024 PNG.

    python3 make_icon.py out.png

Standard library only. gui/icon/build_icns.sh turns the PNG into gui/Resources/AppIcon.icns.
"""
import math
import struct
import sys
import zlib

SIZE = 1024
BOX = 824          # the rounded square, centred, as macOS app icons are drawn
RADIUS = 186
MARGIN = (SIZE - BOX) / 2

BG_TOP = (38, 44, 92)
BG_BOTTOM = (20, 22, 48)
WARP = (244, 236, 220)      # the threads that run top to bottom
WEFT = (240, 164, 76)       # the threads that run left to right

CENTRES = (512 - 158, 512, 512 + 158)
HALF = 47                   # half the width of a thread
REACH = 262                 # how far a thread runs from the centre


def clamp(v, lo=0.0, hi=1.0):
    return lo if v < lo else hi if v > hi else v


def cover(d, soft=1.2):
    """Coverage of a shape whose signed distance at this pixel is `d` (negative inside)."""
    return clamp(0.5 - d / soft)


def rounded_box(x, y, cx, cy, half, r):
    qx = abs(x - cx) - (half - r)
    qy = abs(y - cy) - (half - r)
    return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - r


def capsule(along, across):
    """Signed distance to a thread: `along` is measured from the centre of the icon along the thread,
    `across` from the thread's centre line."""
    a = max(abs(along) - REACH, 0.0)
    return math.hypot(a, across) - HALF


def mix(a, b, t):
    return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t)


def scale(c, f):
    return (c[0] * f, c[1] * f, c[2] * f)


def nearest(v):
    best = min(range(3), key=lambda k: abs(v - CENTRES[k]))
    return best, v - CENTRES[best]


def pixel(px, py):
    x, y = px + 0.5, py + 0.5
    box = rounded_box(x, y, SIZE / 2, SIZE / 2, BOX / 2, RADIUS)
    # A soft shadow below the square, as system icons have.
    shadow = rounded_box(x, y - 14, SIZE / 2, SIZE / 2, BOX / 2, RADIUS)
    shadow_a = 0.30 * clamp(1.0 - shadow / 30.0) ** 2 if shadow > 0 else 0.30
    inside = cover(box)
    if inside <= 0.0:
        return (0, 0, 0, int(255 * shadow_a + 0.5)) if shadow_a > 0.003 else (0, 0, 0, 0)

    t = clamp((y - MARGIN) / BOX)
    colour = mix(BG_TOP, BG_BOTTOM, t)
    # A faint lift toward the top-left corner.
    glow = clamp(1.0 - math.hypot(x - 330, y - 300) / 620.0)
    colour = mix(colour, (70, 80, 150), 0.22 * glow * glow)

    i, dx = nearest(x)      # the warp thread nearest in x, and the offset from its centre line
    j, dy = nearest(y)      # the weft thread nearest in y
    d_warp = capsule(y - 512, dx)
    d_weft = capsule(x - 512, dy)
    warp_on_top = (i + j) % 2 == 0

    def thread(base, across, d_other, other_on_top):
        # Rounder in the middle, darker toward the edges; darker still where it dips under the other.
        f = 1.0 - 0.20 * (across / HALF) ** 2
        if other_on_top and d_other > 0:
            f *= 1.0 - 0.42 * clamp(1.0 - d_other / 22.0) ** 1.5
        return scale(base, f)

    warp = thread(WARP, dx, d_weft, not warp_on_top)
    weft = thread(WEFT, dy, d_warp, warp_on_top)
    order = ((weft, d_weft), (warp, d_warp)) if warp_on_top else ((warp, d_warp), (weft, d_weft))
    for col, d in order:
        a = cover(d)
        if a > 0.0:
            colour = mix(colour, col, a)

    # A thin light edge along the top of the square.
    rim = clamp(1.0 - abs(box + 3.0) / 3.0) * clamp((420 - y) / 300.0)
    colour = mix(colour, (150, 160, 230), 0.35 * rim)

    r, g, b = (int(clamp(c / 255.0) * 255 + 0.5) for c in colour)
    if inside >= 1.0:
        return (r, g, b, 255)
    alpha = inside + shadow_a * (1.0 - inside)
    k = inside / alpha
    return (int(r * k + 0.5), int(g * k + 0.5), int(b * k + 0.5), int(255 * alpha + 0.5))


def png(path):
    rows = bytearray()
    for py in range(SIZE):
        rows.append(0)
        for px in range(SIZE):
            rows.extend(pixel(px, py))

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b""))


if __name__ == "__main__":
    png(sys.argv[1] if len(sys.argv) > 1 else "icon-1024.png")
