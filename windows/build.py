"""Build portable Windows folder; includes no firmware private key or user data."""
from pathlib import Path
import sys
import subprocess
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.tools/python'))
import PyInstaller.__main__
dlls=Path(sys.base_prefix)/'DLLs'
PyInstaller.__main__.run([
    '--noconfirm','--onedir','--windowed','--name','TplinkAC',
    '--paths',str(ROOT/'src'),'--paths',str(ROOT/'.tools/python'),
    '--add-data',str(ROOT/'web')+';web',
    '--add-binary',str(dlls/'libssl-3.dll')+';.',
    '--add-binary',str(dlls/'libcrypto-3.dll')+';.',
    '--distpath',str(ROOT/'dist'),'--workpath',str(ROOT/'build'),
    '--specpath',str(ROOT/'windows'),str(ROOT/'windows/main.py')])
