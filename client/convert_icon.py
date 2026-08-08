#!/usr/bin/env python3
import os
import sys
from pathlib import Path

try:
    from PIL import Image
except Exception:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    from PIL import Image

here = Path(__file__).resolve().parent
orig = here / 'mag.ico'
if not orig.exists():
    # try to find any image in folder
    for ext in ('png','jpg','jpeg'):
        for p in here.glob(f'*.{ext}'):
            orig = p
            break
        if orig.exists():
            break
    else:
        print('No mag.ico or image sources found in', here)
        sys.exit(2)

backup = here / 'mag.ico.bak'
if orig.name == 'mag.ico' and not backup.exists():
    orig.rename(backup)
    print('Backed up original to', backup)
    src_path = backup
else:
    src_path = orig

img = Image.open(src_path)
img = img.convert('RGBA')
# ensure we have at least 256x256 for best results
if img.width < 256 or img.height < 256:
    img = img.resize((256,256), Image.LANCZOS)

out = here / 'mag.ico'
sizes = [(256,256),(48,48),(32,32),(16,16)]
img.save(out, format='ICO', sizes=sizes)
print('Wrote', out, 'with sizes', sizes)

# if we backed up an original file under a different name (e.g., .png), ensure backup not overwritten
sys.exit(0)
