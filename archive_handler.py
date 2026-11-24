
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath


MAX_FILES = 500
MAX_FILE_SIZE = 1024 * 1024       # 1 MB per file
MAX_TOTAL_SIZE = 50 * 1024 * 1024 # 50 MB total
MAX_COMPRESSION_RATIO = 200

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".css", ".json", ".php",
    ".java", ".go", ".rb", ".sql",
    ".yaml", ".yml", ".toml", ".ini"
}


class InvalidArchiveError(Exception):
    pass


def is_supported_file(filename):
    path = Path(filename)

    return (
        path.suffix.lower() in SUPPORTED_EXTENSIONS
        or filename.lower() == ".env"
    )



def extract_zip(zip_path, destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as archive:

            entries = archive.infolist()

            if len(entries) > MAX_FILES:
                raise InvalidArchiveError("Too many files in archive.")

            total_size = 0
            total_written = 0
            extracted_paths = set()

            for entry in entries:

                raw_name = entry.filename
                normalized_name = raw_name.replace("\\", "/")
                relative_path = PurePosixPath(normalized_name)

                if (
                    relative_path.is_absolute()
                    or ".." in relative_path.parts
                    or not relative_path.parts
                    or ":" in normalized_name
                ):
                    raise InvalidArchiveError("Unsafe archive path.")

                if normalized_name.startswith("/"):
                    raise InvalidArchiveError("Absolute paths are not allowed.")

                unix_mode = entry.external_attr >> 16
                file_type = stat.S_IFMT(unix_mode)

                allowed_types = {0, stat.S_IFREG, stat.S_IFDIR}

                if file_type not in allowed_types:
                    raise InvalidArchiveError(
                        "Special filesystem objects are not allowed."
                    )

                if entry.is_dir() and file_type == stat.S_IFREG:
                    raise InvalidArchiveError("Invalid directory entry.")

                if not entry.is_dir() and file_type == stat.S_IFDIR:
                    raise InvalidArchiveError("Invalid file entry.")

                if entry.flag_bits & 0x1:
                    raise InvalidArchiveError(
                        "Encrypted archives are not supported."
                    )

                if entry.is_dir():
                    continue

                if entry.file_size > MAX_FILE_SIZE:
                    raise InvalidArchiveError(
                        "A file in the archive exceeds the 1 MB limit."
                    )

                total_size += entry.file_size

                if total_size > MAX_TOTAL_SIZE:
                    raise InvalidArchiveError("Archive is too large.")

                if entry.file_size > 0:
                    ratio = entry.file_size / max(entry.compress_size, 1)

                    if ratio > MAX_COMPRESSION_RATIO:
                        raise InvalidArchiveError(
                            "Suspicious compression ratio."
                        )

                if not is_supported_file(relative_path.name):
                    continue

                path_key = "/".join(relative_path.parts).casefold()

                if any(
                    path_key == existing
                    or path_key.startswith(existing + "/")
                    or existing.startswith(path_key + "/")
                    for existing in extracted_paths
                ):
                    raise InvalidArchiveError(
                        "Duplicate or conflicting archive paths."
                    )

                extracted_paths.add(path_key)

                target_path = (
                    destination / Path(*relative_path.parts)
                ).resolve()

                if os.path.commonpath(
                    [str(destination), str(target_path)]
                ) != str(destination):
                    raise InvalidArchiveError("Unsafe extraction path.")

                target_path.parent.mkdir(parents=True, exist_ok=True)

                written = 0

                with archive.open(entry, "r") as source:
                    with open(target_path, "xb") as output:

                        while True:
                            chunk = source.read(64 * 1024)

                            if not chunk:
                                break

                            written += len(chunk)
                            total_written += len(chunk)

                            if written > MAX_FILE_SIZE:
                                raise InvalidArchiveError(
                                    "File exceeds size limit."
                                )

                            if total_written > MAX_TOTAL_SIZE:
                                raise InvalidArchiveError(
                                    "Extracted archive exceeds total size limit."
                                )

                            output.write(chunk)

                if written != entry.file_size:
                    raise InvalidArchiveError(
                        "Archive file size mismatch."
                    )

        return destination

    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as error:
        import shutil
        shutil.rmtree(destination, ignore_errors=True)

        if isinstance(error, zipfile.BadZipFile):
            raise InvalidArchiveError("Invalid ZIP archive.")

        raise InvalidArchiveError(
            "Unable to safely process ZIP archive."
        ) from error

    except Exception:
        import shutil
        shutil.rmtree(destination, ignore_errors=True)
        raise
