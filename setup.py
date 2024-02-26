"""Setup for securetar."""
from setuptools import find_packages, setup

LONG_DESC = open("README.md").read()
PACKAGES = find_packages(exclude=["tests", "tests.*"])
REQUIREMENTS = list(val.strip() for val in open("requirements.txt"))
MIN_PY_VERSION = "3.9"

setup(
    name="securetar",
    version="2024.2.1",
    license="Apache License 2.0",
    url="https://github.com/pvizeli/securetar",
    author="Pascal Vizeli",
    author_email="pvizeli@syshack.ch",
    description="Python module to handle tarfile backups.",
    long_description=LONG_DESC,
    long_description_content_type="text/markdown",
    packages=PACKAGES,
    zip_safe=True,
    platforms="any",
    install_requires=REQUIREMENTS,
    python_requires=f">={MIN_PY_VERSION}",
    classifiers=[
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
