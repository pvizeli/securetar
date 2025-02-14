# Secure Tar

Secure Tarfile library

It's a streaming wrapper around python tarfile and allow secure handling files and support encryption.

```python
from securetar import SecureTarFile, atomic_contents_add
from pathlib import Path

path_to_add = Path(".")

with SecureTarFile("test.tar", "w") as tar_file:
    atomic_contents_add(
        tar_file,
        path_to_add,
        file_filter=lambda _: False,
        arcname=".",
    )

with SecureTarFile("test.tar", "w", b"AES128_KEY_SIZE") as tar_file:
    atomic_contents_add(
        tar_file,
        path_to_add,
        file_filter=lambda _: False,
        arcname=".",
    )
```

A common pattern is to create an outer uncompressed tarfile that contains
a variety of inner tar files. This can be accomplished without writing
out multiple files with the following pattern.

```python
from securetar import SecureTarFile, atomic_contents_add
from pathlib import Path

path_1 = Path("path1")
path_2 = Path("path2")

outer_secure_tar_file = SecureTarFile("pkg.tar", "w", gzip=False)

with outer_secure_tar_file as outer_tar_file:
    with outer_secure_tar_file.create_inner_tar(
        "./backup1.tar.gz", gzip=True
    ) as inner_tar_file:
        atomic_contents_add(
            inner_tar_file,
            path_1,
            file_filter=lambda _: False,
            arcname=".",
        )

    with outer_secure_tar_file.create_inner_tar(
        "./backup2.tar.gz", gzip=True
    ) as inner_tar_file:
        atomic_contents_add(
            inner_tar_file,
            path_2,
            file_filter=lambda _: False,
            arcname=".",
        )

```
