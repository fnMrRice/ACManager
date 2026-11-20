"""Create a source bundle with no firmware executables, credentials or live data."""
import tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
output=ROOT/'build/tplink-ac-openwrt.tar.gz'
output.parent.mkdir(exist_ok=True)
with tarfile.open(output,'w:gz') as tar:
    for folder in ('src','web','openwrt'):
        for file in sorted((ROOT/folder).rglob('*')):
            if file.is_file() and '__pycache__' not in file.parts:
                tar.add(file,arcname=file.relative_to(ROOT).as_posix())
print(output,output.stat().st_size)
sdk=ROOT/'build/tplink-ac-sdk-source.tar.gz'
with tarfile.open(sdk,'w:gz') as tar:
    tar.add(ROOT/'package/tplink-ac/Makefile',arcname='tplink-ac/Makefile')
    for folder in ('src','web','openwrt'):
        for file in sorted((ROOT/folder).rglob('*')):
            if file.is_file() and '__pycache__' not in file.parts:
                tar.add(file,arcname='tplink-ac/'+file.relative_to(ROOT).as_posix())
print(sdk,sdk.stat().st_size)
