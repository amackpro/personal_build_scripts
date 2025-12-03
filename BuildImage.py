import os
import sys
import subprocess
from pathlib import Path

def main():
    # Always run from script/.exe location
    os.chdir(Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent)

    # Get folder from drag & drop or input
    folder = sys.argv[1].strip('"') if len(sys.argv) > 1 else input("Enter folder name (system/vendor/odm/product): ").strip().strip('"')
    name = Path(folder).name

    if not Path(name).exists():
        print(f"\nFolder '{name}' not found!")
        input("Press Enter..."); return

    print(f"\nDetected folder: {name}")
    print("1) Build EXT4 image (+50 MiB auto size)")
    print("2) Build EROFS image (uses *_size.txt if exists)")

    while True:
        choice = input("\nChoose (1 or 2): ").strip()
        if choice in ["1", "2"]: break
        print("Please type 1 or 2")

    # Common paths
    config_dir = Path("config")
    fs_config = config_dir / f"{name}_fs_config"
    file_contexts = config_dir / f"{name}_file_contexts"
    size_txt = config_dir / f"{name}_size.txt"
    out_dir = Path(f"pack_output_{name}")
    img_path = out_dir / f"{name}.img"

    if not fs_config.exists():
        print(f"Missing: {fs_config}")
        input("Press Enter..."); return

    # Create output folder
    if out_dir.exists():
        import shutil; shutil.rmtree(out_dir)
    out_dir.mkdir()

    if choice == "1":
        # === EXT4 MODE ===
        print(f"\nBuilding {name}.img (EXT4 +50 MiB)...")
        size = sum(f.stat().st_size for f in Path(name).rglob('*') if f.is_file())
        blocks = (size + 50*1024*1024 + 4095) // 4096
        inodes = sum(1 for _ in open(fs_config)) + 1000

        subprocess.run([
            ".\\bin\\e2fsprogs\\mke2fs.exe",
            "-t", "ext4", "-b", "4096", "-O", "^has_journal",
            "-L", name, "-I", "256", "-M", f"/{name}", "-m", "0",
            "-N", str(inodes), str(img_path), str(blocks)
        ], check=True)

        subprocess.run([
            ".\\bin\\e2fsprogs\\e2fsdroid.exe",
            "-e", "-T", "1230768000",
            "-C", str(fs_config), "-S", str(file_contexts),
            "-f", name, "-a", f"/{name}", str(img_path)
        ], check=True)

        mb = img_path.stat().st_size // 1048576
        print(f"\nEXT4 image created → {mb} MB")

    else:
        # === EROFS MODE ===
        print(f"\nBuilding {name}.img (EROFS)...")
        cmd = [
            ".\\bin\\erofs\\mkfs.erofs.exe",
            "--workers=16", "-zlz4hc,12", "-C", "32768", "-T", "1230768000",
            "--mount-point=/" + name,
            "--fs-config-file=" + str(fs_config),
            "--file-contexts=" + str(file_contexts),
            str(img_path), name
        ]
        subprocess.run(cmd, check=True)
        mb = img_path.stat().st_size // 1048576
        print(f"\nEROFS image created → {mb} MB")

    print(f"\nLocation: {img_path.resolve()}\n")
    input("Done! Press Enter to exit...")

if __name__ == "__main__":
    main()