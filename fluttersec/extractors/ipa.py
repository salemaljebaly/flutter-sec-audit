"""
IPA file extraction and analysis
"""
import zipfile
import plistlib
from pathlib import Path
from typing import Optional, List, Dict
import tempfile
import shutil


class IPAExtractor:
    """Extract and analyze iOS IPA files"""

    def __init__(self, ipa_path: str):
        self.ipa_path = Path(ipa_path)
        if not self.ipa_path.exists():
            raise FileNotFoundError(f"IPA file not found: {ipa_path}")

        self.extract_dir: Optional[Path] = None
        self.payload_dir: Optional[Path] = None
        self.app_dir: Optional[Path] = None
        self.bundle_id: Optional[str] = None
        self.app_name: Optional[str] = None

    def extract(self, output_dir: Optional[str] = None) -> Path:
        """Extract IPA contents to directory"""
        if output_dir:
            self.extract_dir = Path(output_dir)
            self.extract_dir.mkdir(parents=True, exist_ok=True)
        else:
            # Use temp directory if no output specified
            self.extract_dir = Path(tempfile.mkdtemp(prefix="fluttersec_ipa_"))

        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
                zip_ref.extractall(self.extract_dir)
        except zipfile.BadZipFile:
            raise ValueError(f"Invalid IPA file: {self.ipa_path}")

        # Find Payload directory
        self.payload_dir = self.extract_dir / "Payload"
        if not self.payload_dir.exists():
            raise ValueError("Invalid IPA structure: Payload directory not found")

        # Find .app directory
        app_dirs = list(self.payload_dir.glob("*.app"))
        if not app_dirs:
            raise ValueError("Invalid IPA structure: .app directory not found")

        self.app_dir = app_dirs[0]

        # Parse Info.plist to get bundle ID and app name
        self._parse_info_plist()

        return self.extract_dir

    def _parse_info_plist(self) -> None:
        """Parse Info.plist to extract app metadata"""
        if not self.app_dir:
            return

        info_plist = self.app_dir / "Info.plist"
        if not info_plist.exists():
            return

        try:
            with open(info_plist, 'rb') as f:
                plist_data = plistlib.load(f)

            self.bundle_id = plist_data.get('CFBundleIdentifier')
            self.app_name = plist_data.get('CFBundleDisplayName') or \
                           plist_data.get('CFBundleName')
        except Exception:
            pass

    def find_files(self, pattern: str) -> List[Path]:
        """Find files matching pattern in extracted IPA"""
        if not self.extract_dir:
            raise RuntimeError("IPA not extracted yet. Call extract() first.")

        return list(self.extract_dir.rglob(pattern))

    def get_flutter_assets_dir(self) -> Optional[Path]:
        """Get flutter_assets directory if it exists"""
        if not self.app_dir:
            return None

        # In iOS, flutter assets are in Frameworks/App.framework/flutter_assets
        flutter_assets = self.app_dir / "Frameworks" / "App.framework" / "flutter_assets"
        return flutter_assets if flutter_assets.exists() else None

    def get_app_binary(self) -> Optional[Path]:
        """Get main app binary (contains Dart code)"""
        if not self.app_dir:
            return None

        # Try Frameworks/App.framework/App
        app_binary = self.app_dir / "Frameworks" / "App.framework" / "App"
        if app_binary.exists():
            return app_binary

        # Fallback: app binary with same name as .app directory
        app_name = self.app_dir.stem
        app_binary = self.app_dir / app_name
        return app_binary if app_binary.exists() else None

    def get_info_plist(self) -> Optional[Path]:
        """Get Info.plist file"""
        if not self.app_dir:
            return None

        info_plist = self.app_dir / "Info.plist"
        return info_plist if info_plist.exists() else None

    def get_entitlements(self) -> Optional[Dict]:
        """Extract entitlements from app (requires codesign tool on macOS)"""
        # This would require running codesign command
        # For now, return None as it needs native tools
        return None

    def list_all_files(self) -> List[str]:
        """List all files in the IPA"""
        if not self.extract_dir:
            return []

        files = []
        for file_path in self.extract_dir.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(self.extract_dir)
                files.append(str(rel_path))
        return sorted(files)

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
        if not self.app_dir:
            return False

        # Check for flutter_assets
        if self.get_flutter_assets_dir():
            return True

        # Check for Flutter.framework
        flutter_framework = self.app_dir / "Frameworks" / "Flutter.framework"
        if flutter_framework.exists():
            return True

        return False

    def read_plist(self, plist_path: Path) -> Optional[Dict]:
        """Read and parse a plist file"""
        try:
            with open(plist_path, 'rb') as f:
                return plistlib.load(f)
        except Exception:
            return None

    def cleanup(self) -> None:
        """Clean up extracted files"""
        if self.extract_dir and self.extract_dir.exists():
            if "fluttersec" in str(self.extract_dir):  # Safety check
                shutil.rmtree(self.extract_dir)
                self.extract_dir = None
