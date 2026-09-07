"""Project-controlled build definition for the reviewed sqlcipher3-compatible wheel."""

import os
import stat
import sys
from pathlib import Path

from setuptools import Extension, setup


DISTRIBUTION_NAME = "continuum-sqlcipher3"
MODULE_NAME = "sqlcipher3"
VERSION = "0.6.2.post1"
EXPECTED_BINDING_SOURCES = {
    "src/blob.c",
    "src/cache.c",
    "src/connection.c",
    "src/cursor.c",
    "src/microprotocols.c",
    "src/module.c",
    "src/prepare_protocol.c",
    "src/row.c",
    "src/statement.c",
    "src/util.c",
}


def required_path(name: str, *, directory: bool = False) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError("%s is required" % name)
    path = Path(value)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("%s must name an existing absolute path" % name) from error
    valid = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not valid
        or (not directory and metadata.st_nlink != 1)
    ):
        raise RuntimeError("%s must name an unlinked absolute path of the expected type" % name)
    return str(path)


def build_extension() -> Extension:
    openssl_include = required_path("CONTINUUM_OPENSSL_INCLUDE", directory=True)
    libcrypto = required_path("CONTINUUM_LIBCRYPTO_A")
    binding_sources = {str(path) for path in Path("src").glob("*.c")}
    if binding_sources != EXPECTED_BINDING_SOURCES:
        raise RuntimeError("reviewed binding C source inventory changed")
    sources = sorted(binding_sources) + ["vendor/sqlite3.c"]
    if Path("vendor/sqlite3.c").is_symlink() or Path("vendor/sqlite3.h").is_symlink():
        raise RuntimeError("SQLCipher amalgamation must not be linked")
    if not Path("vendor/sqlite3.c").is_file() or not Path("vendor/sqlite3.h").is_file():
        raise RuntimeError("reviewed binding or SQLCipher amalgamation is incomplete")

    macros = [
        ("MODULE_NAME", '"sqlcipher3.dbapi2"'),
        ("SQLITE_ENABLE_FTS3", "1"),
        ("SQLITE_ENABLE_FTS3_PARENTHESIS", "1"),
        ("SQLITE_ENABLE_FTS4", "1"),
        ("SQLITE_ENABLE_FTS5", "1"),
        ("SQLITE_ENABLE_JSON1", "1"),
        ("SQLITE_ENABLE_LOAD_EXTENSION", "1"),
        ("SQLITE_ENABLE_RTREE", "1"),
        ("SQLITE_ENABLE_STAT4", "1"),
        ("SQLITE_ENABLE_UPDATE_DELETE_LIMIT", "1"),
        ("SQLITE_SOUNDEX", "1"),
        ("SQLITE_USE_URI", "1"),
        ("SQLITE_HAS_CODEC", "1"),
        ("SQLITE_TEMP_STORE", "2"),
        ("SQLITE_THREADSAFE", "1"),
        ("SQLITE_EXTRA_INIT", "sqlcipher_extra_init"),
        ("SQLITE_EXTRA_SHUTDOWN", "sqlcipher_extra_shutdown"),
        ("HAVE_STDINT_H", "1"),
        ("SQLITE_MAX_VARIABLE_NUMBER", "250000"),
        ("SQLITE_DEFAULT_PAGE_SIZE", "4096"),
        ("SQLITE_DEFAULT_CACHE_SIZE", "-8000"),
        ("inline", "__inline"),
    ]
    compile_args = [
        "-O2",
        "-g0",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-U_FORTIFY_SOURCE",
        "-D_FORTIFY_SOURCE=3",
    ]
    link_args = ["-lm"]
    if sys.platform == "darwin":
        compile_args.append("-Qunused-arguments")
    elif sys.platform.startswith("linux"):
        link_args.extend(
            [
                "-ldl",
                "-pthread",
                "-Wl,--as-needed",
                "-Wl,--exclude-libs,ALL",
                "-Wl,-z,noexecstack",
                "-Wl,-z,now",
                "-Wl,-z,relro",
            ]
        )
    else:
        raise RuntimeError("this focused supply-chain gate supports Linux and macOS only")

    return Extension(
        name="sqlcipher3._sqlite3",
        sources=sources,
        define_macros=macros,
        include_dirs=["./src", openssl_include],
        extra_objects=[libcrypto],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
        language="c",
    )


setup(
    name=DISTRIBUTION_NAME,
    version=VERSION,
    description="Continuum Memory reviewed sqlcipher3-compatible native binding",
    long_description=Path("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Charles Leifer, laggykiller, and upstream contributors",
    url="https://github.com/Oussamoux1234/continuum-memory",
    project_urls={
        "Build source": "https://github.com/Oussamoux1234/continuum-memory/issues/13",
        "Upstream binding": "https://github.com/coleifer/sqlcipher3/tree/0.6.2",
    },
    packages=[MODULE_NAME],
    package_dir={MODULE_NAME: MODULE_NAME},
    python_requires=">=3.11,<3.15",
    ext_modules=[build_extension()],
    license_files=["LICENSE", "THIRD_PARTY_LICENSES/*.txt"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: C",
        "Topic :: Database :: Database Engines/Servers",
    ],
)
