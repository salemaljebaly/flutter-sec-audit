"""
APK file extraction and analysis
"""
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, List, Dict
import tempfile
import shutil


class APKExtractor:
    """Extract and analyze Android APK files"""

    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        self.extract_dir: Optional[Path] = None
        self.package_name: Optional[str] = None
        self.app_name: Optional[str] = None

    def extract(self, output_dir: Optional[str] = None) -> Path:
        """Extract APK contents to directory"""
        if output_dir:
            self.extract_dir = Path(output_dir)
            self.extract_dir.mkdir(parents=True, exist_ok=True)
        else:
            # Use temp directory if no output specified
            self.extract_dir = Path(tempfile.mkdtemp(prefix="fluttersec_apk_"))

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.extract_dir)
        except zipfile.BadZipFile:
            raise ValueError(f"Invalid APK file: {self.apk_path}")

        return self.extract_dir

    def find_files(self, pattern: str) -> List[Path]:
        """Find files matching pattern in extracted APK"""
        if not self.extract_dir:
            raise RuntimeError("APK not extracted yet. Call extract() first.")

        return list(self.extract_dir.rglob(pattern))

    def get_flutter_assets_dir(self) -> Optional[Path]:
        """Get flutter_assets directory if it exists"""
        if not self.extract_dir:
            return None

        flutter_assets = self.extract_dir / "assets" / "flutter_assets"
        return flutter_assets if flutter_assets.exists() else None

    def get_native_libs_dir(self, arch: str = "arm64-v8a") -> Optional[Path]:
        """Get native libraries directory"""
        if not self.extract_dir:
            return None

        lib_dir = self.extract_dir / "lib" / arch
        return lib_dir if lib_dir.exists() else None

    def get_libapp(self, arch: str = "arm64-v8a") -> Optional[Path]:
        """Get libapp.so file (contains Dart code)"""
        lib_dir = self.get_native_libs_dir(arch)
        if not lib_dir:
            return None

        libapp = lib_dir / "libapp.so"
        return libapp if libapp.exists() else None

    def list_all_files(self) -> List[str]:
        """List all files in the APK"""
        if not self.extract_dir:
            return []

        files = []
        for file_path in self.extract_dir.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(self.extract_dir)
                files.append(str(rel_path))
        return sorted(files)

    def get_manifest_path(self) -> Optional[Path]:
        """Get AndroidManifest.xml path (will be binary)"""
        if not self.extract_dir:
            return None

        manifest = self.extract_dir / "AndroidManifest.xml"
        return manifest if manifest.exists() else None

    def extract_strings_from_binary(self, binary_path: Path, min_length: int = 4) -> List[str]:
        """Extract readable strings from binary file"""
        strings = []
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            current_string = []
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= min_length:
                        strings.append(''.join(current_string))
                    current_string = []

            # Don't forget last string
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))

        except Exception:
            pass

        return strings

    def detect_flutter(self) -> bool:
        """Check if this is a Flutter app"""
        if not self.extract_dir:
            return False

        # Check for flutter_assets
        if self.get_flutter_assets_dir():
            return True

        # Check for libflutter.so
        lib_dir = self.get_native_libs_dir()
        if lib_dir and (lib_dir / "libflutter.so").exists():
            return True

        return False

    def cleanup(self) -> None:
        """Clean up extracted files"""
        if self.extract_dir and self.extract_dir.exists():
            if "fluttersec" in str(self.extract_dir):  # Safety check
                shutil.rmtree(self.extract_dir)
                self.extract_dir = None
