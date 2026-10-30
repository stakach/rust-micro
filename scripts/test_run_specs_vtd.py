#!/usr/bin/env python3
"""Check the QEMU VT-d topology against the kernel's four-level IOPT ABI."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


RUN_SPECS = Path(__file__).with_name("run_specs.sh")


class RunSpecsVtdTest(unittest.TestCase):
    def test_launcher_requests_four_level_vtd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copy2(RUN_SPECS, scripts / "run_specs.sh")
            (root / ".tmp").mkdir()
            (root / ".tmp" / "disk.img").touch()
            firmware = root / "firmware.fd"
            firmware.touch()

            binaries = root / "bin"
            binaries.mkdir()
            qemu = binaries / "qemu-system-x86_64"
            qemu.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$@" > "$QEMU_ARGS_FILE"\n'
                "exit 1\n"
            )
            qemu.chmod(0o755)
            arguments = root / "qemu-args.txt"
            environment = dict(os.environ)
            environment.update(
                PATH=f"{binaries}{os.pathsep}{environment.get('PATH', '')}",
                OVMF=str(firmware),
                QEMU_ARGS_FILE=str(arguments),
                GRAPHICS="0",
            )
            result = subprocess.run(
                ["bash", str(scripts / "run_specs.sh")],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            args = arguments.read_text().splitlines()
            self.assertIn(
                ("-device", "intel-iommu,intremap=off,aw-bits=48"),
                zip(args, args[1:]),
            )


if __name__ == "__main__":
    unittest.main()
