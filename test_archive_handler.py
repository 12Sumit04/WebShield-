
import tempfile
import unittest
import zipfile

from pathlib import Path

from backend.archive_handler import (
    extract_zip,
    InvalidArchiveError,
    MAX_FILE_SIZE,
)


class TestArchiveHandler(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        self.zip_path = self.root / "test.zip"
        self.destination = self.root / "extracted"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_valid_zip_extraction(self):
        with zipfile.ZipFile(self.zip_path, "w") as archive:
            archive.writestr("app.py", "print('Hello WebShield')")

        extract_zip(self.zip_path, self.destination)

        self.assertTrue((self.destination / "app.py").exists())

    def test_path_traversal_rejected(self):
        outside_file = self.root / "outside.py"

        with zipfile.ZipFile(self.zip_path, "w") as archive:
            archive.writestr("../outside.py", "malicious content")

        with self.assertRaises(InvalidArchiveError):
            extract_zip(self.zip_path, self.destination)

        self.assertFalse(outside_file.exists())

    def test_oversized_file_rejected(self):
        large_content = b"A" * (MAX_FILE_SIZE + 1)

        with zipfile.ZipFile(self.zip_path, "w") as archive:
            archive.writestr("large.py", large_content)

        with self.assertRaises(InvalidArchiveError):
            extract_zip(self.zip_path, self.destination)

    def test_duplicate_case_insensitive_paths_rejected(self):
        with zipfile.ZipFile(self.zip_path, "w") as archive:
            archive.writestr("App.py", "first")
            archive.writestr("app.py", "second")

        with self.assertRaises(InvalidArchiveError):
            extract_zip(self.zip_path, self.destination)


    def test_too_many_files_rejected(self):
        with zipfile.ZipFile(self.zip_path, "w") as archive:
            for index in range(501):
                archive.writestr(f"file_{index}.py", "print('test')")

        with self.assertRaises(InvalidArchiveError):
            extract_zip(self.zip_path, self.destination)

    def test_high_compression_ratio_rejected(self):
        content = b"A" * 100_000

        with zipfile.ZipFile(
            self.zip_path, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr("compressed.py", content)

        with self.assertRaises(InvalidArchiveError):
            extract_zip(self.zip_path, self.destination)

    def test_invalid_zip_rejected(self):
        self.zip_path.write_bytes(b"This is not a valid ZIP archive")

        with self.assertRaises(InvalidArchiveError):
            extract_zip(self.zip_path, self.destination)

    def test_partial_extraction_on_failure(self):
        with zipfile.ZipFile(self.zip_path, "w") as archive:
            archive.writestr("safe.py", "print('safe')")
            archive.writestr("../outside.py", "malicious content")

        with self.assertRaises(InvalidArchiveError):
            extract_zip(self.zip_path, self.destination)

        self.assertFalse(
            (self.destination / "safe.py").exists()
        )

        self.assertFalse(
            (self.root / "outside.py").exists()
        )



if __name__ == "__main__":
    unittest.main()
