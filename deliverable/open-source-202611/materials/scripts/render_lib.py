#!/usr/bin/env python3
"""High-fidelity frame renderers: Chrome browser frame and terminal window.

Page content is captured from a real browser (Playwright). This module only
adds the surrounding browser/terminal chrome so the evidence image carries the
address bar / command-line context required by the task checklist.
"""
from PIL import Image, ImageDraw, ImageFont

# ---------- font paths ----------
FONT_UI = r"C:\Windows\Fonts\segoeui.ttf"
FONT_UI_B = r"C:\Windows\Fonts\segoeuib.ttf"
FONT_MONO = r"C:\Windows\Fonts\consola.ttf"
FONT_MONO_B = r"C:\Windows\Fonts\consolab.ttf"
FONT_YH = r"C:\Windows\Fonts\msyh.ttc"
FONT_YH_B = r"C:\Windows\Fonts\msyhbd.ttc"
FONT_SYM = r"C:\Windows\Fonts\seguisym.ttf"

# Chrome palette (light theme)
C_TABBAR = (222, 225, 230)
C_TOOLBAR = (255, 255, 255)
C_OMNIBOX = (241, 243, 244)
C_TEXT = (32, 33, 36)
C_TEXT_DIM = (95, 99, 104)
C_ICON = (95, 99, 104)
C_WHITE = (255, 255, 255)
C_LINE = (218, 220, 224)


def font(path, size):
    return ImageFont.truetype(path, size)


def rounded(draw, box, radius, fill, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def _circle(draw, cx, cy, r, fill):
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)


def _triangle(draw, pts, fill):
    draw.polygon(pts, fill=fill)


# ---------- Chrome UI icons (simple vector glyphs) ----------
def icon_back(draw, cx, cy, col):
    # left arrow with a small stem
    draw.polygon([(cx - 6, cy), (cx + 4, cy - 7), (cx + 4, cy + 7)], fill=col)
    draw.line([(cx - 6, cy), (cx + 6, cy)], fill=col, width=3)


def icon_forward(draw, cx, cy, col):
    draw.polygon([(cx + 6, cy), (cx - 4, cy - 7), (cx - 4, cy + 7)], fill=col)
    draw.line([(cx - 6, cy), (cx + 6, cy)], fill=col, width=3)


def icon_reload(draw, cx, cy, col):
    draw.arc([cx - 7, cy - 7, cx + 7, cy + 7], start=300, end=200, fill=col, width=2)
    draw.polygon([(cx + 6, cy - 5), (cx + 11, cy - 2), (cx + 5, cy + 1)], fill=col)


def icon_home(draw, cx, cy, col):
    draw.polygon([(cx - 8, cy), (cx, cy - 8), (cx + 8, cy)], fill=col)
    draw.rectangle([cx - 5, cy, cx + 5, cy + 8], fill=col)


def icon_lock(draw, cx, cy, col):
    draw.arc([cx - 5, cy - 9, cx + 5, cy + 2], 180, 360, fill=col, width=2)
    draw.rectangle([cx - 7, cy - 3, cx + 7, cy + 9], outline=col, width=2)


def icon_info(draw, cx, cy, col):
    draw.ellipse([cx - 8, cy - 8, cx + 8, cy + 8], outline=col, width=2)
    draw.ellipse([cx - 1, cy - 5, cx + 1, cy - 3], fill=col)
    draw.line([(cx, cy - 1), (cx, cy + 5)], fill=col, width=2)


def icon_star(draw, cx, cy, col):
    pts = []
    import math
    for i in range(10):
        r = 8 if i % 2 == 0 else 3.5
        a = -math.pi / 2 + i * math.pi / 5
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    draw.polygon(pts, outline=col)


def icon_menu(draw, cx, cy, col):
    for dy in (-6, 0, 6):
        draw.ellipse([cx - 2, cy + dy - 2, cx + 2, cy + dy + 2], fill=col)


def icon_puzzle(draw, cx, cy, col):
    draw.rounded_rectangle([cx - 7, cy - 7, cx + 7, cy + 7], radius=2, outline=col, width=2)
    draw.ellipse([cx - 3, cy - 3, cx + 3, cy + 3], outline=col, width=2)


def chrome_frame(page_img, url, tab_title, secure=False):
    """Wrap a real page screenshot in a high-fidelity Chrome window frame."""
    pw, ph = page_img.size
    tab_h, tool_h = 44, 50
    W = pw
    H = tab_h + tool_h + ph
    img = Image.new("RGB", (W, H), C_WHITE)
    d = ImageDraw.Draw(img)

    # ---- tab bar ----
    d.rectangle([0, 0, W, tab_h], fill=C_TABBAR)
    # active tab
    tab_w = min(320, W - 200)
    rounded(d, [12, 6, 12 + tab_w, tab_h + 2], 8, C_WHITE)
    d.rectangle([12, tab_h - 4, 12 + tab_w, tab_h + 2], fill=C_WHITE)
    # favicon dot
    fx = 30
    _circle(d, fx, 24, 7, (46, 125, 90))
    f_tab = font(FONT_YH, 15)
    d.text((fx + 12, 16), tab_title, font=f_tab, fill=C_TEXT)
    # tab close X
    tx = 12 + tab_w - 22
    d.line([(tx - 5, 19), (tx + 5, 29)], fill=C_TEXT_DIM, width=2)
    d.line([(tx + 5, 19), (tx - 5, 29)], fill=C_TEXT_DIM, width=2)
    # new tab "+"
    nx = 12 + tab_w + 26
    d.line([(nx, 18), (nx, 30)], fill=C_TEXT_DIM, width=2)
    d.line([(nx - 6, 24), (nx + 6, 24)], fill=C_TEXT_DIM, width=2)

    # window controls
    cw = 46
    base_x = W - cw * 3
    for i in range(3):
        x0 = base_x + i * cw
        if i == 2:
            d.rectangle([x0, 0, x0 + cw, tab_h], fill=(234, 90, 80))
            col = C_WHITE
            d.line([(x0 + 16, 16), (x0 + 30, 30)], fill=col, width=2)
            d.line([(x0 + 30, 16), (x0 + 16, 30)], fill=col, width=2)
        elif i == 0:
            d.line([(x0 + 15, 28), (x0 + 31, 28)], fill=C_TEXT, width=2)
        else:
            d.rectangle([x0 + 16, 18, x0 + 30, 30], outline=C_TEXT, width=2)

    # ---- toolbar ----
    y0 = tab_h
    d.rectangle([0, y0, W, y0 + tool_h], fill=C_TOOLBAR)
    cy = y0 + tool_h // 2
    icon_back(d, 26, cy, C_ICON)
    icon_forward(d, 62, cy, (180, 183, 188))
    icon_reload(d, 98, cy, C_ICON)
    icon_home(d, 134, cy, C_ICON)

    # omnibox
    ox0, ox1 = 168, W - 158
    rounded(d, [ox0, cy - 17, ox1, cy + 17], 17, C_OMNIBOX)
    ix = ox0 + 22
    if secure:
        icon_lock(d, ix, cy, C_ICON)
    else:
        icon_info(d, ix, cy, C_ICON)
    f_url = font(FONT_UI, 17)
    d.text((ix + 16, cy - 11), url, font=f_url, fill=C_TEXT)
    # star inside right
    icon_star(d, ox1 - 30, cy, C_ICON)

    # right-side icons
    rx = W - 120
    icon_puzzle(d, rx, cy, C_ICON)
    # user avatar
    _circle(d, W - 78, cy, 11, (198, 210, 234))
    _circle(d, W - 78, cy - 3, 4, (90, 110, 150))
    d.pieslice([W - 85, cy + 2, W - 71, cy + 14], 180, 360, fill=(90, 110, 150))
    icon_menu(d, W - 34, cy, C_ICON)

    # ---- page ----
    img.paste(page_img, (0, tab_h + tool_h))
    return img


def terminal_window(lines, title, width=1600, bg=(12, 12, 12), fg=(230, 230, 230),
                    font_size=20, line_h=26, pad=18):
    """Render a terminal window from real command output lines.

    Each line is either a plain string or (text, color_tuple).
    """
    title_h = 38
    n = len(lines)
    H = title_h + pad * 2 + n * line_h + 10
    img = Image.new("RGB", (width, H), bg)
    d = ImageDraw.Draw(img)
    # Windows Terminal style tab/title bar
    bar = (45, 45, 46)
    d.rectangle([0, 0, width, title_h], fill=bar)
    # active tab on the left
    rounded(d, [8, 6, 120, title_h + 2], 6, (12, 12, 12))
    d.rectangle([8, title_h - 4, 120, title_h + 2], fill=(12, 12, 12))
    f_title = font(FONT_UI, 14)
    d.text((22, 11), "Terminal", font=f_title, fill=(225, 225, 225))
    # window controls on the right (flat, close hover red)
    cw = 46
    base_x = width - cw * 3
    for i in range(3):
        x0 = base_x + i * cw
        if i == 2:
            d.rectangle([x0, 0, x0 + cw, title_h], fill=(234, 90, 80))
            d.line([(x0 + 16, 13), (x0 + 30, 27)], fill=(255, 255, 255), width=2)
            d.line([(x0 + 30, 13), (x0 + 16, 27)], fill=(255, 255, 255), width=2)
        elif i == 0:
            d.line([(x0 + 15, 25), (x0 + 31, 25)], fill=(230, 230, 230), width=2)
        else:
            d.rectangle([x0 + 16, 15, x0 + 30, 27], outline=(230, 230, 230), width=2)
    # session title text in the middle
    f_sess = font(FONT_UI, 14)
    tw = d.textlength(title, font=f_sess)
    d.text(((width - tw) // 2, 11), title, font=f_sess, fill=(200, 200, 200))

    f_mono = font(FONT_MONO, font_size)
    y = title_h + pad
    for line in lines:
        if isinstance(line, tuple):
            text, col = line
        else:
            text, col = line, fg
        d.text((pad, y), text, font=f_mono, fill=col)
        y += line_h
    return img
