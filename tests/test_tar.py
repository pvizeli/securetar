"""Test Tarfile functions."""

import gzip
import io
import os
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePath
from unittest.mock import patch
import pytest

from securetar import (
    SecureTarFile,
    _is_excluded_by_filter,
    _add_stream,
    atomic_contents_add,
    secure_path,
)


@dataclass
class TarInfo:
    """Fake TarInfo."""

    name: str


def test_secure_path() -> None:
    """Test Secure Path."""
    test_list = [
        TarInfo("test.txt"),
        TarInfo("data/xy.blob"),
        TarInfo("bla/blu/ble"),
        TarInfo("data/../xy.blob"),
    ]
    assert test_list == list(secure_path(test_list))


def test_not_secure_path() -> None:
    """Test Not secure path."""
    test_list = [
        TarInfo("/test.txt"),
        TarInfo("data/../../xy.blob"),
        TarInfo("/bla/blu/ble"),
    ]
    assert [] == list(secure_path(test_list))


def test_is_excluded_by_filter_good() -> None:
    """Test exclude filter."""
    filter_list = ["not/match", "/dev/xy"]
    test_list = [
        PurePath("test.txt"),
        PurePath("data/xy.blob"),
        PurePath("bla/blu/ble"),
        PurePath("data/../xy.blob"),
    ]

    for path_object in test_list:
        assert _is_excluded_by_filter(path_object, filter_list) is False


def test_is_exclude_by_filter_bad() -> None:
    """Test exclude filter."""
    filter_list = ["*.txt", "data/*", "bla/blu/ble"]
    test_list = [
        PurePath("test.txt"),
        PurePath("data/xy.blob"),
        PurePath("bla/blu/ble"),
        PurePath("data/test_files/kk.txt"),
    ]

    for path_object in test_list:
        assert _is_excluded_by_filter(path_object, filter_list) is True


@pytest.mark.parametrize("bufsize", [10240, 4 * 2**20])
def test_create_pure_tar(tmp_path: Path, bufsize: int) -> None:
    """Test to create a tar file without encryption."""
    # Prepare test folder
    temp_orig = tmp_path.joinpath("orig")
    fixture_data = Path(__file__).parent.joinpath("fixtures/tar_data")
    shutil.copytree(fixture_data, temp_orig, symlinks=True)

    # Create Tarfile
    temp_tar = tmp_path.joinpath("backup.tar")
    with SecureTarFile(temp_tar, "w", bufsize=bufsize) as tar_file:
        atomic_contents_add(
            tar_file,
            temp_orig,
            excludes=[],
            arcname=".",
        )

    assert temp_tar.exists()

    # Restore
    temp_new = tmp_path.joinpath("new")
    with SecureTarFile(temp_tar, "r", bufsize=bufsize) as tar_file:
        tar_file.extractall(path=temp_new, members=tar_file)

    assert temp_new.is_dir()
    assert temp_new.joinpath("test_symlink").is_symlink()
    assert temp_new.joinpath("test1").is_dir()
    assert temp_new.joinpath("test1/script.sh").is_file()

    # 775 is correct for local, but in GitHub action it's 755, both is fine
    assert oct(temp_new.joinpath("test1/script.sh").stat().st_mode)[-3:] in [
        "755",
        "775",
    ]
    assert temp_new.joinpath("README.md").is_file()


@pytest.mark.parametrize("bufsize", [10240, 4 * 2**20])
def test_create_encrypted_tar(tmp_path: Path, bufsize: int) -> None:
    """Test to create a tar file with encryption."""
    key = os.urandom(16)

    # Prepare test folder
    temp_orig = tmp_path.joinpath("orig")
    fixture_data = Path(__file__).parent.joinpath("fixtures/tar_data")
    shutil.copytree(fixture_data, temp_orig, symlinks=True)

    # Create Tarfile
    temp_tar = tmp_path.joinpath("backup.tar")
    with SecureTarFile(temp_tar, "w", key=key, bufsize=bufsize) as tar_file:
        atomic_contents_add(
            tar_file,
            temp_orig,
            excludes=[],
            arcname=".",
        )

    assert temp_tar.exists()

    # Restore
    temp_new = tmp_path.joinpath("new")
    with SecureTarFile(temp_tar, "r", key=key, bufsize=bufsize) as tar_file:
        tar_file.extractall(path=temp_new, members=tar_file)

    assert temp_new.is_dir()
    assert temp_new.joinpath("test_symlink").is_symlink()
    assert temp_new.joinpath("test1").is_dir()
    assert temp_new.joinpath("test1/script.sh").is_file()

    # 775 is correct for local, but in GitHub action it's 755, both is fine
    assert oct(temp_new.joinpath("test1/script.sh").stat().st_mode)[-3:] in [
        "755",
        "775",
    ]
    assert temp_new.joinpath("README.md").is_file()


def test_gzipped_tar_inside_tar(tmp_path: Path) -> None:
    # Prepare test folder
    temp_orig = tmp_path.joinpath("orig")
    fixture_data = Path(__file__).parent.joinpath("fixtures/tar_data")
    shutil.copytree(fixture_data, temp_orig, symlinks=True)

    # Create Tarfile
    main_tar = tmp_path.joinpath("backup.tar")
    inner_tgz_files = ("core.tar.gz", "core2.tar.gz", "core3.tar.gz")
    outer_secure_tar_file = SecureTarFile(main_tar, "w", gzip=False)
    with outer_secure_tar_file as outer_tar_file:
        for inner_tgz_file in inner_tgz_files:
            with outer_secure_tar_file.create_inner_tar(
                inner_tgz_file, gzip=True
            ) as inner_tar_file:
                atomic_contents_add(
                    inner_tar_file,
                    temp_orig,
                    excludes=[],
                    arcname=".",
                )

        assert len(outer_tar_file.getmembers()) == 3

        raw_bytes = b'{"test": "test"}'
        fileobj = io.BytesIO(raw_bytes)
        tar_info = tarfile.TarInfo(name="backup.json")
        tar_info.size = len(raw_bytes)
        tar_info.mtime = time.time()
        outer_tar_file.addfile(tar_info, fileobj=fileobj)
        assert len(outer_tar_file.getmembers()) == 4

    assert main_tar.exists()
    # Restore
    temp_new = tmp_path.joinpath("new")
    with SecureTarFile(main_tar, "r", gzip=False) as tar_file:
        tar_file.extractall(path=temp_new)

    assert temp_new.is_dir()
    core_tar_gz = temp_new.joinpath("core.tar.gz")
    assert core_tar_gz.is_file()
    compressed = core_tar_gz.read_bytes()
    uncompressed = gzip.decompress(core_tar_gz.read_bytes())
    assert len(uncompressed) > len(compressed)

    assert temp_new.joinpath("core2.tar.gz").is_file()
    assert temp_new.joinpath("core3.tar.gz").is_file()
    backup_json = temp_new.joinpath("backup.json")
    assert backup_json.is_file()
    assert backup_json.read_bytes() == raw_bytes

    # Extract inner tars
    for inner_tgz in inner_tgz_files:
        temp_inner_new = tmp_path.joinpath("{inner_tgz}_inner_new")

        with SecureTarFile(temp_new.joinpath(inner_tgz), "r", gzip=True) as tar_file:
            tar_file.extractall(path=temp_inner_new, members=tar_file)

        assert temp_inner_new.is_dir()
        assert temp_inner_new.joinpath("test_symlink").is_symlink()
        assert temp_inner_new.joinpath("test1").is_dir()
        assert temp_inner_new.joinpath("test1/script.sh").is_file()

        # 775 is correct for local, but in GitHub action it's 755, both is fine
        assert oct(temp_inner_new.joinpath("test1/script.sh").stat().st_mode)[-3:] in [
            "755",
            "775",
        ]
        assert temp_inner_new.joinpath("README.md").is_file()


def test_gzipped_tar_inside_tar_failure(tmp_path: Path) -> None:
    # Prepare test folder
    temp_orig = tmp_path.joinpath("orig")
    fixture_data = Path(__file__).parent.joinpath("fixtures/tar_data")
    shutil.copytree(fixture_data, temp_orig, symlinks=True)

    # Create Tarfile
    main_tar = tmp_path.joinpath("backup.tar")
    outer_secure_tar_file = SecureTarFile(main_tar, "w", gzip=False)
    with outer_secure_tar_file as outer_tar_file:
        # Make the first tar file to ensure that
        # the second tar file can still be created
        with pytest.raises(ValueError, match="Test"):
            with outer_secure_tar_file.create_inner_tar(
                "failed.tar.gz", gzip=True
            ) as inner_tar_file:
                raise ValueError("Test")

        with pytest.raises(ValueError, match="Test"):
            with outer_secure_tar_file.create_inner_tar(
                "good.tar.gz", gzip=True
            ) as inner_tar_file:
                atomic_contents_add(
                    inner_tar_file,
                    temp_orig,
                    excludes=[],
                    arcname=".",
                )
                raise ValueError("Test")

        assert len(outer_tar_file.getmembers()) == 2

    assert main_tar.exists()
    # Restore
    temp_new = tmp_path.joinpath("new")
    with SecureTarFile(main_tar, "r", gzip=False) as tar_file:
        tar_file.extractall(path=temp_new)

    assert temp_new.is_dir()
    assert temp_new.joinpath("good.tar.gz").is_file()

    failed_path = temp_new.joinpath("failed.tar.gz")
    assert failed_path.is_file()

    # Extract inner tar
    temp_inner_new = tmp_path.joinpath("good.tar.gz_inner_new")

    with SecureTarFile(temp_new.joinpath("good.tar.gz"), "r", gzip=True) as tar_file:
        tar_file.extractall(path=temp_inner_new, members=tar_file)

    assert temp_inner_new.is_dir()
    assert temp_inner_new.joinpath("test_symlink").is_symlink()
    assert temp_inner_new.joinpath("test1").is_dir()
    assert temp_inner_new.joinpath("test1/script.sh").is_file()

    # 775 is correct for local, but in GitHub action it's 755, both is fine
    assert oct(temp_inner_new.joinpath("test1/script.sh").stat().st_mode)[-3:] in [
        "755",
        "775",
    ]
    assert temp_inner_new.joinpath("README.md").is_file()

    # Extract failed inner tar (should not raise but will be empty)
    temp_inner_new = tmp_path.joinpath("failed.tar.gz_inner_new")

    with SecureTarFile(temp_new.joinpath("failed.tar.gz"), "r", gzip=True) as tar_file:
        tar_file.extractall(path=temp_inner_new, members=tar_file)


def test_encrypted_gzipped_tar_inside_tar(tmp_path: Path) -> None:
    key = os.urandom(16)

    # Prepare test folder
    temp_orig = tmp_path.joinpath("orig")
    fixture_data = Path(__file__).parent.joinpath("fixtures/tar_data")
    shutil.copytree(fixture_data, temp_orig, symlinks=True)

    # Create Tarfile
    main_tar = tmp_path.joinpath("backup.tar")
    inner_tgz_files = ("core.tar.gz", "core2.tar.gz", "core3.tar.gz")
    outer_secure_tar_file = SecureTarFile(main_tar, "w", gzip=False)
    with outer_secure_tar_file as outer_tar_file:
        for inner_tgz_file in inner_tgz_files:
            with outer_secure_tar_file.create_inner_tar(
                inner_tgz_file, key=key, gzip=True
            ) as inner_tar_file:
                atomic_contents_add(
                    inner_tar_file,
                    temp_orig,
                    excludes=[],
                    arcname=".",
                )

        assert len(outer_tar_file.getmembers()) == 3

    assert main_tar.exists()
    # Restore
    temp_new = tmp_path.joinpath("new")
    with SecureTarFile(main_tar, "r", gzip=False) as tar_file:
        tar_file.extractall(path=temp_new)

    assert temp_new.is_dir()
    assert temp_new.joinpath("core.tar.gz").is_file()
    assert temp_new.joinpath("core2.tar.gz").is_file()
    assert temp_new.joinpath("core3.tar.gz").is_file()

    # Extract inner encrypted tars
    for inner_tgz in inner_tgz_files:
        temp_inner_new = tmp_path.joinpath("{inner_tgz}_inner_new")

        with SecureTarFile(
            temp_new.joinpath(inner_tgz), "r", key=key, gzip=True
        ) as tar_file:
            tar_file.extractall(path=temp_inner_new, members=tar_file)

        assert temp_inner_new.is_dir()
        assert temp_inner_new.joinpath("test_symlink").is_symlink()
        assert temp_inner_new.joinpath("test1").is_dir()
        assert temp_inner_new.joinpath("test1/script.sh").is_file()

        # 775 is correct for local, but in GitHub action it's 755, both is fine
        assert oct(temp_inner_new.joinpath("test1/script.sh").stat().st_mode)[-3:] in [
            "755",
            "775",
        ]
        assert temp_inner_new.joinpath("README.md").is_file()


def test_inner_tar_not_allowed_in_encrypted(tmp_path: Path) -> None:
    # Create Tarfile
    main_tar = tmp_path.joinpath("backup.tar")
    key = os.urandom(16)

    outer_secure_tar_file = SecureTarFile(main_tar, "w", key=key, gzip=False)

    with pytest.raises(tarfile.StreamError):
        with outer_secure_tar_file:
            with outer_secure_tar_file.create_inner_tar("any.tgz", gzip=True):
                pass


def test_outer_tar_must_not_be_compressed(tmp_path: Path) -> None:
    # Create Tarfile
    main_tar = tmp_path.joinpath("backup.tar.gz")
    outer_secure_tar_file = SecureTarFile(main_tar, "w", gzip=True)

    with pytest.raises(OSError):
        with outer_secure_tar_file:
            with outer_secure_tar_file.create_inner_tar("any.tgz", gzip=True):
                pass


@pytest.mark.parametrize(
    "format", [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT]
)
def test_tar_stream(tmp_path: Path, format: int) -> None:
    # Prepare test folder
    temp_orig = tmp_path.joinpath("orig")
    fixture_data = Path(__file__).parent.joinpath("fixtures/tar_data")
    shutil.copytree(fixture_data, temp_orig, symlinks=True)

    # Create Tarfile
    main_tar = tmp_path.joinpath("backup.tar")

    with patch.object(tarfile, "DEFAULT_FORMAT", format):
        with SecureTarFile(main_tar, "w", gzip=False) as tar_file:
            tar_info = tarfile.TarInfo(name="test.txt")
            with _add_stream(tar_file, tar_info) as stream:
                stream.write(b"test")

        # Restore
        temp_new = tmp_path.joinpath("new")
        with SecureTarFile(main_tar, "r", gzip=False) as tar_file:
            tar_file.extractall(path=temp_new)

        assert temp_new.is_dir()
        test_file = temp_new.joinpath("test.txt")
        assert test_file.is_file()
        assert test_file.read_bytes() == b"test"
