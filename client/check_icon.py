#!/usr/bin/env python3
from PIL import Image
from pathlib import Path
p = Path(__file__).resolve().parent / 'mag.ico'
if not p.exists():
    print('mag.ico not found at', p)
    raise SystemExit(2)
im = Image.open(p)
sizes = []
try:
    n = getattr(im, 'n_frames', 1)
    for f in range(n):
        im.seek(f)
        sizes.append(im.size)
except Exception:
    pass
print('MAG.ICO SIZES:', sizes)
