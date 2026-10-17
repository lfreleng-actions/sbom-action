#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Print the PEP 508 marker environment of the running interpreter.

The python backend runs this with the SCANNED environment's interpreter
so that markers are judged against the Python the SBOM describes,
measured rather than assumed equal to the one the action's tools run
on. It runs as 'python -I -S': -S skips the site module, so the .pth
files the installed packages carry never execute, and -I keeps the
working directory and PYTHON* variables out of the module path. That
environment holds none of the action's packages, so this uses the
standard library alone.

The fields and their derivation follow packaging.markers'
default_environment().
"""

from __future__ import annotations

import json
import os
import platform
import sys


def format_version(info: sys._version_info) -> str:  # pyright: ignore[reportPrivateUsage]
    """Render a version_info as PEP 508 expects, e.g. 3.13.0rc1."""
    version = f"{info.major}.{info.minor}.{info.micro}"
    if info.releaselevel != "final":
        version += info.releaselevel[0] + str(info.serial)
    return version


def main() -> int:
    """Write the environment as one JSON object."""
    environment = {
        "implementation_name": sys.implementation.name,
        "implementation_version": format_version(sys.implementation.version),
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "platform_python_implementation": platform.python_implementation(),
        "python_version": ".".join(platform.python_version_tuple()[:2]),
        "sys_platform": sys.platform,
    }
    print(json.dumps(environment))
    return 0


if __name__ == "__main__":
    sys.exit(main())
