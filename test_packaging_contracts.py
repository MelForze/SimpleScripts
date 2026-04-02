import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import packaging_backend


ROOT = Path(__file__).resolve().parent
PYPROJECT_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)


class PackagingContractsTests(unittest.TestCase):
    def test_backend_version_matches_pyproject(self):
        pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = PYPROJECT_VERSION_RE.search(pyproject_text)
        self.assertIsNotNone(match, "pyproject.toml must define project version")
        self.assertEqual(
            match.group(1),
            packaging_backend.VERSION,
            "packaging_backend.VERSION must match pyproject.toml version",
        )

    def test_script_sources_exist_with_exact_case(self):
        packaging_backend._validate_script_sources()

    def test_wheel_build_smoke_contains_new_scanner(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    ".",
                    "--no-deps",
                    "--wheel-dir",
                    tmpdir,
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            wheels = list(Path(tmpdir).glob(f"simplescripts-{packaging_backend.VERSION}-*.whl"))
            self.assertEqual(len(wheels), 1)

            with zipfile.ZipFile(wheels[0]) as archive:
                names = set(archive.namelist())

            self.assertIn(
                f"simplescripts-{packaging_backend.VERSION}.dist-info/entry_points.txt",
                names,
            )
            self.assertIn(
                "simplescripts_scripts/Scanners/masscan_to_httpx.py",
                names,
            )


if __name__ == "__main__":
    unittest.main()
