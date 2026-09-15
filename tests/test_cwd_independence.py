import os
import subprocess
import sys
import unittest
from pathlib import Path


class TestLaunchFromAnyDirectory(unittest.TestCase):
    def test_help_works_outside_project_directory(self):
        project = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            [sys.executable, str(project / "main.py"), "--help"],
            cwd="/tmp",
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("AutoVAPT v2", proc.stdout)

    def test_dependency_check_works_outside_project_directory(self):
        project = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            [sys.executable, str(project / "main.py"), "--check-dependencies"],
            cwd="/tmp",
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Core framework: Ready", proc.stdout)
