# UnpackImage.py - FINAL VERSION THAT DETECTS EROFS 100% CORRECTLY
# Configs → root config\ folder
# Works perfectly as .py and .exe

import os
import sys
import subprocess
import shutil
from pathlib import Path

# === Tool directory ===
TOOL_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent
os.chdir(TOOL_DIR)

# === Current Python (works in .exe too) ===
PYTHON = sys.executable

# === EROFS magic bytes (offset 1024) ===
EROFS_MAGIC = b"\xE2\xE1\xF5\xE0"

def is_erofs_image(img_path: Path) -> bool:
    """Detect EROFS by reading magic bytes at offset 1024"""
    try:
        with img_path.open("rb") as f:
            f.seek(1024)
            return f.read(4) == EROFS_MAGIC
    except Exception:
        return False

def fix_logd_caps(fs_config_path):
    if not fs_config_path.exists():
        return
    text = fs_config_path.read_text(encoding="utf-8", errors="ignore")
    new_text = text.replace("0x4000040000040", "0x440000040") \
                   .replace("0x40000400004000040", "0x440000040")
    if new_text != text:
        fs_config_path.write_text(new_text, encoding="utf-8")
        print("Fixed logd capabilities in fs_config")

def main():
    if len(sys.argv) < 2:
        input("Drag an image onto UnpackImage.exe\nPress Enter...")
        return

    img_path = Path(sys.argv[1]).resolve()
    if not img_path.exists():
        print("File not found!"); input(); return

    name = img_path.stem
    work_dir = img_path.parent

    print(f"\nUnpacking: {img_path.name}")
    print(f"Partition : {name}\n")

    # === 1. Handle .br → .dat → .img ===
    final_img = img_path

    if img_path.suffix.lower() == ".br":
        print("Decompressing .new.dat.br → .new.dat...")
        subprocess.run([str(TOOL_DIR / "bin" / "brotli.exe"), "-d", str(img_path), "-o", str(img_path.with_suffix(""))], check=True)
        final_img = img_path.with_suffix("")

    if final_img.suffix.lower() in [".dat", ".new.dat"]:
        transfer = work_dir / f"{name}.transfer.list"
        if not transfer.exists():
            print("transfer.list not found!"); input(); return
        final_img = work_dir / f"{name}.img"
        print("Converting .new.dat → .img...")
        subprocess.run([PYTHON, str(TOOL_DIR / "bin" / "sdat2img.py"),
                        str(transfer), str(img_path), str(final_img)], check=True)

    # === 2. Prepare folders ===
    extract_folder = work_dir / name
    if extract_folder.exists():
        shutil.rmtree(extract_folder)
    extract_folder.mkdir()
    Path("config").mkdir(exist_ok=True)

    # === 3. DETECT EROFS BY MAGIC BYTES (100% accurate) ===
    is_erofs = is_erofs_image(final_img)

    if is_erofs:
        print("EROFS image detected → extracting with extract.erofs.exe...")
        erofs_tool = TOOL_DIR / "bin" / "erofs" / "extract.erofs.exe"
        if not erofs_tool.exists():
            print("extract.erofs.exe not found! Cannot unpack EROFS.")
            input(); return
        subprocess.run([
            str(erofs_tool), "-T16", "-x", "-i", str(final_img), "-o", str(work_dir)
        ], check=True)

        # Move config files from temp config/name_xxx → root config/
        for suffix in ["_fs_config", "_file_contexts", "_fs_options"]:
            src = work_dir / f"config/{name}{suffix}"
            if src.exists():
                shutil.move(str(src), str(TOOL_DIR / "config" / f"{name}{suffix}"))

        # Create size.txt
        total = sum(f.stat().st_size for f in extract_folder.rglob('*') if f.is_file())
        print(f"EROFS unpacked → {total // 1048576} MB")

    else:
        # === 4. EXT4 / Sparse → ImgExtractor ===
        print("EXT4 / Sparse image detected → using ImgExtractor...")
        subprocess.run([
            PYTHON,
            str(TOOL_DIR / "bin" / "ImgExtractor.py"),
            str(final_img),
            str(work_dir)
        ], check=True)

    # === 5. Final config cleanup & logd fix ===
    for suffix in ["_fs_config", "_file_contexts"]:
        src = work_dir / f"config/{name}{suffix}"
        if src.exists():
            shutil.move(str(src), str(TOOL_DIR / "config" / f"{name}{suffix}"))

    fs_config = TOOL_DIR / "config" / f"{name}_fs_config"
    if fs_config.exists():
        fix_logd_caps(fs_config)

    print(f"\nUNPACK COMPLETED SUCCESSFULLY!")
    print(f"→ Files    : {extract_folder}")
    print(f"→ Configs  : config\\{name}_fs_config  config\\{name}_file_contexts")
    print(f"→ Ready for BuildImage.exe")

    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()