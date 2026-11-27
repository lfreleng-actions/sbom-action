# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Find the module BOMs a Maven build wrote, for maven_merge.

Each module whose build binds cyclonedx-maven-plugin's makeBom leaves
target/bom.json beside its pom.xml. A BOM the repository owning its
module tracks, or one behind a symlink, is not the build's output and
is skipped with a warning.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field

BOM = os.path.join("target", "bom.json")

# core.fsmonitor is forced off, since a repository's own configuration
# could otherwise name a program for git to run.
GIT = ("git", "-c", "core.fsmonitor=false")

# Variables that would point git at a repository other than the one
# owning the module.
GIT_ENVIRONMENT = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
)


def shown(value: str) -> str:
    """Escape workflow-command metacharacters, % first."""
    for raw, escaped in (("%", "%25"), ("\r", "%0D"), ("\n", "%0A")):
        value = value.replace(raw, escaped)
    return value


def warn(message: str) -> None:
    """Print a workflow warning."""
    print(f"::warning::{shown(message)}")


def in_repository(directory: str) -> bool:
    """Whether a .git entry lies at or above ``directory``."""
    current = os.path.abspath(directory)
    while True:
        if os.path.lexists(os.path.join(current, ".git")):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def git_tracked(module: str) -> bool | None:
    """Whether the repository owning ``module`` tracks its BOM.

    None means git could not answer: git is missing, or it refuses a
    repository it considers of dubious ownership. A module in no
    repository at all tracks nothing.
    """
    if not in_repository(module):
        return False
    environment = {
        key: value for key, value in os.environ.items() if key not in GIT_ENVIRONMENT
    }
    try:
        listed = subprocess.run(
            [*GIT, "-C", module, "ls-files", "-z", "--", BOM],
            capture_output=True,
            check=True,
            env=environment,
            timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return bool(listed)


@dataclass
class Discovery:
    """What the walk found under the top directory."""

    boms: list[str] = field(default_factory=lambda: list[str]())
    tracked: list[str] = field(default_factory=lambda: list[str]())
    linked: list[str] = field(default_factory=lambda: list[str]())
    missing: list[str] = field(default_factory=lambda: list[str]())


def discover(top: str) -> Discovery:
    """Find each module's BOM under ``top``, in a stable order."""
    found = Discovery()
    for path, dirs, files in os.walk(top):
        in_src = os.path.basename(path) == "src"
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in ("target", ".git") and not (in_src and name == "it")
        )
        if "pom.xml" not in files:
            continue
        bom = os.path.join(path, BOM)
        # git checks the alias, not what a link points at, so a linked
        # target or BOM could pass off a tracked file, or one outside
        # path_prefix, as this build's output.
        linked = os.path.islink(os.path.dirname(bom)) or os.path.islink(bom)
        if not (os.path.lexists(bom) if linked else os.path.isfile(bom)):
            found.missing.append(path)
            continue
        state = True if linked else git_tracked(path)
        if state:
            why = "it is behind a symlink" if linked else "the repository tracks it"
            warn(
                f"Skipped {relative(bom, top)}: {why},"
                + " so it is not trusted as this build's output."
            )
            (found.linked if linked else found.tracked).append(bom)
            continue
        if state is None:
            warn(
                "Could not ask git whether the repository tracks"
                + f" {relative(bom, top)}; merging it as the build's output."
            )
        found.boms.append(bom)
    return found


def relative(path: str, top: str) -> str:
    """Name ``path`` relative to ``top`` for the log."""
    return os.path.normpath(os.path.relpath(path, top))
