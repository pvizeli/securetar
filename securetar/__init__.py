"""Tarfile fileobject handler for encrypted files."""

from __future__ import annotations

from collections.abc import Callable, Generator
import hashlib
import logging
import os
import tarfile
import time
from contextlib import contextmanager
from pathlib import Path, PurePath
from typing import IO, BinaryIO

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)

BLOCK_SIZE = 16
BLOCK_SIZE_BITS = 128
IV_SIZE = BLOCK_SIZE
DEFAULT_BUFSIZE = 10240

SECURETAR_MAGIC = b"SecureTar\x02\x00\x00\x00\x00\x00\x00"
SECURETAR_HEADER_SIZE = len(SECURETAR_MAGIC) + 16

GZIP_MAGIC_BYTES = b"\x1f\x8b\x08"
TAR_MAGIC_BYTES = b"ustar"
TAR_MAGIC_OFFSET = 257

MOD_READ = "r"
MOD_WRITE = "w"


class SecureTarHeader:
    """SecureTar header.

    Reads and produces the SecureTar header. Also accepts the magic-less
    format used in earlier releases of SecureTar.
    """

    def __init__(self, cbc_rand: bytes, plaintext_size: int | None) -> None:
        """Initialize SecureTar header."""
        self.cbc_rand = cbc_rand
        self.plaintext_size = plaintext_size

    @classmethod
    def from_bytes(cls, f: IO[bytes]) -> SecureTarHeader:
        """Return header bytes."""
        header = f.read(len(SECURETAR_MAGIC))
        plaintext_size: int | None = None
        if header != SECURETAR_MAGIC:
            cbc_rand = header
        else:
            plaintext_size = int.from_bytes(f.read(8), "big")
            f.read(8)  # Skip reserved bytes
            cbc_rand = f.read(IV_SIZE)

        return cls(cbc_rand, plaintext_size)

    def to_bytes(self) -> bytes:
        """Return header bytes."""
        if self.plaintext_size is None:
            raise ValueError("Plaintext size is required")
        return (
            SECURETAR_MAGIC
            + self.plaintext_size.to_bytes(8, "big")
            + bytes(8)
            + self.cbc_rand
        )


class SecureTarError(Exception):
    """SecureTar error."""


class SecureTarReadError(SecureTarError):
    """SecureTar read error."""


class SecureTarFile:
    """Handle encrypted files for tarfile library."""

    def __init__(
        self,
        name: Path | None = None,
        mode: str = "r",
        key: bytes | None = None,
        gzip: bool = True,
        bufsize: int = DEFAULT_BUFSIZE,
        fileobj: IO[bytes] | None = None,
    ) -> None:
        """Initialize encryption handler."""
        self._file: IO[bytes] | None = None
        self._mode: str = mode
        self._name: Path | None = name
        self._bufsize: int = bufsize
        self._extra_args = {}
        self._fileobj = fileobj

        # Tarfile options
        self._tar: tarfile.TarFile | None = None
        if key:
            self._tar_mode = f"{mode}|"
        else:
            self._tar_mode = f"{mode}:"
            if gzip:
                self._extra_args["compresslevel"] = 6

        if gzip:
            self._tar_mode = self._tar_mode + "gz"

        # Encryption/Description
        self._aes: Cipher | None = None
        self._key: bytes | None = key

        # Function helper
        self._decrypt: CipherContext | None = None
        self._encrypt: CipherContext | None = None
        self._padder: padding.PaddingContext | None = None
        self.padding_length = 0

        self.securetar_header: SecureTarHeader | None = None

    def create_inner_tar(
        self, name: str, key: bytes | None = None, gzip: bool = True
    ) -> "_InnerSecureTarFile":
        """Create inner tar file."""
        return _InnerSecureTarFile(
            self._tar,
            name=Path(name),
            mode=self._mode,
            key=key,
            gzip=gzip,
            bufsize=self._bufsize,
        )

    def __enter__(self) -> tarfile.TarFile:
        """Start context manager tarfile."""
        if not self._key:
            self._tar = tarfile.open(
                name=str(self._name),
                mode=self._tar_mode,
                dereference=False,
                bufsize=self._bufsize,
                **self._extra_args,
                **({"fileobj": self._fileobj} if self._fileobj else {}),
            )
            return self._tar

        # Encrypted/Decrypted Tarfile
        self._open_file()
        self._setup_cipher()

        self._tar = tarfile.open(
            fileobj=self,
            mode=self._tar_mode,
            dereference=False,
            bufsize=self._bufsize,
        )
        return self._tar

    def _open_file(self) -> None:
        if self._fileobj:
            # If we have a fileobj, we don't need to open a file
            self._file = self._fileobj
        else:
            if not self._name:
                raise ValueError("No filename or fileobj provided")
            read_mode = self._mode.startswith("r")
            if read_mode:
                file_mode: int = os.O_RDONLY
            else:
                file_mode = os.O_WRONLY | os.O_CREAT

            fd = os.open(self._name, file_mode, 0o666)
            self._file = os.fdopen(fd, "rb" if read_mode else "wb")

    def _setup_cipher(self) -> None:
        # Extract IV for CBC
        if self._mode == MOD_READ:
            self.securetar_header = SecureTarHeader.from_bytes(self._file)
            cbc_rand = self.securetar_header.cbc_rand
        else:
            cbc_rand = os.urandom(IV_SIZE)
            self.securetar_header = SecureTarHeader(cbc_rand, 0)
            self._file.write(self.securetar_header.to_bytes())

        # Create Cipher
        self._aes = Cipher(
            algorithms.AES(self._key),
            modes.CBC(_generate_iv(self._key, cbc_rand)),
            backend=default_backend(),
        )

        self._decrypt = self._aes.decryptor()
        self._encrypt = self._aes.encryptor()
        self._padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Close file."""
        if self._tar:
            self._tar.close()
            self._tar = None
        self._close_file()

    def _close_file(self) -> None:
        """Close file."""
        if self._file:
            if not self._mode.startswith("r"):
                padding = self._padder.finalize()
                self._file.write(self._encrypt.update(padding))
                self.padding_length = len(padding)
            if not self._fileobj:
                self._file.close()
            self._file = None

    @contextmanager
    def decrypt(self, tarinfo: tarfile.TarInfo) -> Generator[BinaryIO, None, None]:
        """Decrypt inner tar.

        This is a helper to decrypt data and discard the padding.
        """

        class DecryptInnerTar:
            """Decrypt inner tar file."""

            def __init__(self, parent: SecureTarFile) -> None:
                """Initialize."""
                self._head: bytes | None = None
                self._parent = parent
                self._pos = 0
                self._size = tarinfo.size - IV_SIZE
                self._tail: bytes | None = None
                if parent.securetar_header.plaintext_size is not None:
                    self._size -= SECURETAR_HEADER_SIZE

            @staticmethod
            def _validate_inner_tar(head: bytes) -> None:
                """Validate inner tar."""
                if (
                    head[0 : len(GZIP_MAGIC_BYTES)] != GZIP_MAGIC_BYTES
                    and head[TAR_MAGIC_OFFSET : TAR_MAGIC_OFFSET + len(TAR_MAGIC_BYTES)]
                    != TAR_MAGIC_BYTES
                ):
                    raise SecureTarReadError(
                        "The inner tar is not gzip or tar, wrong key?"
                    )

            def read(self, size: int = 0) -> bytes:
                """Read data."""
                if self._head is None:
                    # Read and validate header
                    self._head = self._parent.read(max(size, 512))
                    self._validate_inner_tar(self._head)

                if self._tail is not None:
                    # Finish reading tail
                    data = self._tail[:size]
                    self._tail = self._tail[size:]
                    return data

                if self._head:
                    # Read from head
                    data = self._head[:size]
                    self._head = self._head[size:]
                    remaining = size - len(data)
                    if remaining:
                        data += self._parent.read(remaining)
                else:
                    data = self._parent.read(size)

                self._pos += len(data)
                if not data or self._size - self._pos > BLOCK_SIZE:
                    return data

                # Last block: Append any remaining head, read tail and discard padding
                if self._head:
                    data += self._head
                data += self._parent.read(self._size - self._pos)
                padding_len = data[-1]
                data = data[:-padding_len]
                self._tail = data[size:]
                return data[:size]

        try:
            self._open_file()
            self._setup_cipher()
            yield DecryptInnerTar(self)
        finally:
            self._close_file()

    def write(self, data: bytes) -> None:
        """Write data."""
        data = self._padder.update(data)
        self._file.write(self._encrypt.update(data))

    def read(self, size: int = 0) -> bytes:
        """Read data."""
        return self._decrypt.update(self._file.read(size))

    @property
    def path(self) -> Path:
        """Return path object of tarfile."""
        return self._name

    @property
    def size(self) -> float:
        """Return backup size."""
        if not self._name.is_file():
            return 0
        return round(self._name.stat().st_size / 1_048_576, 2)  # calc mbyte


class _InnerSecureTarFile(SecureTarFile):
    """Handle encrypted files for tarfile library inside another tarfile."""

    def __init__(
        self,
        outer_tar: tarfile.TarFile,
        name: Path,
        mode: str,
        key: bytes | None = None,
        gzip: bool = True,
        bufsize: int = DEFAULT_BUFSIZE,
    ) -> None:
        """Initialize inner handler."""
        super().__init__(
            name=name,
            mode=mode,
            key=key,
            gzip=gzip,
            bufsize=bufsize,
            fileobj=outer_tar.fileobj,
        )
        self.outer_tar = outer_tar
        self.stream: Generator[BinaryIO, None, None] | None = None

    def __enter__(self) -> tarfile.TarFile:
        """Start context manager tarfile."""
        tar_info = tarfile.TarInfo(name=str(self._name))
        if self.outer_tar.format == tarfile.PAX_FORMAT:
            # Ensure we always set mtime as a float to force
            # a PAX header to be written.
            #
            # This is necessary to
            # handle large files as TarInfo.tobuf will try to
            # use a shorter ustar header if we do not have at
            # least one float in the tarinfo.
            # https://github.com/python/cpython/blob/53b84e772cac6e4a55cebf908d6bb9c48fe254dc/Lib/tarfile.py#L1066
            tar_info.mtime = time.time()
        else:
            tar_info.mtime = int(time.time())
        self.stream = _add_stream(self.outer_tar, tar_info, self)
        self.stream.__enter__()
        return super().__enter__()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Close file."""
        super().__exit__(exc_type, exc_value, traceback)
        self.stream.__exit__(exc_type, exc_value, traceback)


@contextmanager
def _add_stream(
    tar: tarfile.TarFile, tar_info: tarfile.TarInfo, inner_tar: _InnerSecureTarFile
) -> Generator[BinaryIO, None, None]:
    """Add a stream to the tarfile.

    This only works with uncompressed, unencrypted tar files.

    The typical usage is:

    with _add_stream(tar, tar_info) as fileobj:
        fileobj.write(data)

    It is critical that the tar_info is not modified
    inside the context manager, as the tar file header
    size may change.

    :param tar: The outer tar file to add the stream to.
    :param tar_info: TarInfo for the added stream.
    :param padding: PKCS7 padding added at the end of the stream. If non-empty,
    the inner tar is encrypted, and we calculate the plaintext size from the padding
    and add a pax header with the plaintext size. If empty, the inner tar is not
    encrypted and we don't add a plaintext size pax header.
    """
    fileobj = tar.fileobj
    tell_before_adding_inner_file_header = fileobj.tell()
    # Write an empty header for the inner tar file
    # We'll seek back to this position later to update the header with the correct size
    tar_info_header = tar_info.tobuf(tar.format, tar.encoding, tar.errors)
    tar_info_header_len = len(tar_info_header)
    fileobj.write(tar_info_header)
    try:
        yield fileobj
    finally:
        tell_after_writing_inner_tar = fileobj.tell()
        size_of_inner_tar = (
            tell_after_writing_inner_tar
            - tell_before_adding_inner_file_header
            - tar_info_header_len
        )
        # Pad the outer tar file to a multiple of BLOCKSIZE
        # in case the inner tar file is not a multiple of BLOCKSIZE
        blocks, remainder = divmod(size_of_inner_tar, tarfile.BLOCKSIZE)
        padding_size = 0
        if remainder > 0:
            padding_size = tarfile.BLOCKSIZE - remainder
            fileobj.write(tarfile.NUL * padding_size)
            blocks += 1
        tar.offset += size_of_inner_tar + padding_size

        tar_info.size = size_of_inner_tar
        if inner_tar.padding_length:
            # Update the size in the header
            inner_tar.securetar_header.plaintext_size = (
                size_of_inner_tar
                - inner_tar.padding_length
                - IV_SIZE
                - SECURETAR_HEADER_SIZE
            )
            fileobj.seek(tell_before_adding_inner_file_header + tar_info_header_len)
            tar.fileobj.write(inner_tar.securetar_header.to_bytes())
        # Now that we know the size of the inner tar, we seek back
        # to where we started and re-add the member with the correct size
        fileobj.seek(tell_before_adding_inner_file_header)
        # We can't call tar.addfile here because it doesn't allow a non-zero
        # size to be set without passing a fileobj. Instead we manually write
        # the header. https://github.com/python/cpython/pull/117988
        buf = tar_info.tobuf(tar.format, tar.encoding, tar.errors)
        tar.fileobj.write(buf)
        tar.offset += len(buf)
        tar.members.append(tar_info)
        # Finally return to the end of the outer tar file
        fileobj.seek(tell_after_writing_inner_tar + padding_size)


def _generate_iv(key: bytes, salt: bytes) -> bytes:
    """Generate an iv from data."""
    temp_iv = key + salt
    for _ in range(100):
        temp_iv = hashlib.sha256(temp_iv).digest()
    return temp_iv[:IV_SIZE]


def secure_path(tar: tarfile.TarFile) -> Generator[tarfile.TarInfo, None, None]:
    """Security safe check of path.
    Prevent ../ or absolut paths
    """
    for member in tar:
        file_path = Path(member.name)
        try:
            if file_path.is_absolute():
                raise ValueError()
            Path("/fake", file_path).resolve().relative_to("/fake")
        except (ValueError, RuntimeError):
            _LOGGER.warning("Found issue with file %s", file_path)
            continue
        else:
            yield member


def atomic_contents_add(
    tar_file: tarfile.TarFile,
    origin_path: Path,
    file_filter: Callable[[PurePath], bool],
    arcname: str = ".",
) -> None:
    """Append directories and/or files to the TarFile if file_filter returns False.

    :param file_filter: A filter function, should return True if the item should
    be excluded from the archive. The function should take a single argument, a
    pathlib.PurePath object representing the relative path of the item to be archived.
    """

    if file_filter(PurePath(arcname)):
        return None
    return _atomic_contents_add(tar_file, origin_path, file_filter, arcname)


def _atomic_contents_add(
    tar_file: tarfile.TarFile,
    origin_path: Path,
    file_filter: Callable[[PurePath], bool],
    arcname: str,
) -> None:
    """Append directories and/or files to the TarFile if file_filter returns False."""

    # Add directory only (recursive=False) to ensure we also archive empty directories
    tar_file.add(origin_path.as_posix(), arcname=arcname, recursive=False)

    for directory_item in origin_path.iterdir():
        item_arcpath = PurePath(arcname, directory_item.name)
        if file_filter(PurePath(item_arcpath)):
            continue

        item_arcname = item_arcpath.as_posix()
        if directory_item.is_dir() and not directory_item.is_symlink():
            _atomic_contents_add(tar_file, directory_item, file_filter, item_arcname)
            continue

        tar_file.add(directory_item.as_posix(), arcname=item_arcname, recursive=False)

    return None
