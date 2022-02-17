# Secure Tar
Secure Tarfile library

It's a streaming wrapper around python tarfile and allow secure handling files and support encryption.


```python

with SecureTarFile("test.tar", "w") as tar_file:
        atomic_contents_add(
            tar_file,
            temp_orig,
            excludes=[],
            arcname=".",
        )

with SecureTarFile("test.tar", "w", b"AES128_KEY_SIZE") as tar_file:
        atomic_contents_add(
            tar_file,
            temp_orig,
            excludes=[],
            arcname=".",
        )

```

