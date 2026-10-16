# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Read a project's pyproject.toml for the python backend.

cyclonedx-py takes the SBOM's root component from --pyproject, and
links that root to each installed distribution the file names as a
dependency, by name alone. Handing it the project's own file has four
problems:

- When the file carries a [tool.poetry] table, cyclonedx-py reads that
  table for the root's name and raises KeyError when it has none, which
  is the normal Poetry 2 layout of a PEP 621 [project] table alongside
  [tool.poetry] settings (measured on cyclonedx-bom 7.5.0).
- It links the root to every installed package named in
  [project.optional-dependencies]. An extra installed solely because a
  development group also names it would then read as a runtime
  dependency of the project.
- It ignores environment markers, so 'six; python_version < "3"'
  becomes a root edge on Python 3 wherever something else installed six.
- A project whose dependencies are dynamic declares none in the file,
  so the root would carry no edges at all.

So the action anchors the root on a copy holding the [project] table
alone, less optional-dependencies, whose dependencies are the ones
that apply to the scanned environment: each requirement, static or
taken from the installed project's metadata (Requires-Dist) when
dynamic, whose marker holds for that interpreter with no extra
selected, written without its marker.
"""

from __future__ import annotations

import json
import re
import sys
from importlib.metadata import distributions
from typing import cast

# Ships with cyclonedx-bom, whose environment runs this script
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet

# Python 3.10, the oldest python_version accepts, lacks tomllib; the
# action installs tomli alongside this script for it
if sys.version_info >= (3, 11):  # noqa: UP036
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # pyright: ignore[reportUnreachable]

Table = dict[str, object]


def as_table(value: object) -> Table | None:
    """Return a parsed TOML table, or None for any other value."""
    if isinstance(value, dict):
        return cast("Table", value)
    return None


def as_list(value: object) -> list[object] | None:
    """Return a parsed TOML array, or None for any other value."""
    if isinstance(value, list):
        return cast("list[object]", value)
    return None


def toml_value(value: object) -> str:
    """Render a parsed TOML value back as TOML inline syntax."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        # JSON string syntax is TOML basic-string syntax, apart from
        # DEL, which TOML requires escaped and JSON leaves alone.
        # ensure_ascii=False keeps non-BMP characters out of the
        # surrogate-pair escapes TOML rejects.
        return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")
    items = as_list(value)
    if items is not None:
        return "[" + ", ".join(toml_value(item) for item in items) + "]"
    table = as_table(value)
    if table is not None:
        pairs = (
            f"{toml_value(key)} = {toml_value(item)}" for key, item in table.items()
        )
        return "{" + ", ".join(pairs) + "}"
    # Dates and times: never part of a valid [project] table
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def canonical(name: str) -> str:
    """Normalise a distribution name as PEP 503 does."""
    return re.sub(r"[-_.]+", "-", name).lower()


def marker_environment(markers: str) -> dict[str, str]:
    """Return the scanned interpreter's PEP 508 marker environment.

    This script runs on the tools' interpreter, not the scanned one, so
    every field comes from the scanned interpreter's own report rather
    than an assumption that the two agree. No extra is selected.
    """
    with open(markers, encoding="utf-8") as handle:
        parsed = as_table(cast("object", json.load(handle)))
    if parsed is None:
        raise ValueError("the marker environment is not a JSON object")
    environment = {key: str(value) for key, value in parsed.items()}
    environment["extra"] = ""
    return environment


def applicable(requirements: list[str], environment: dict[str, str]) -> list[str]:
    """Return the requirements whose markers hold, without the markers.

    A requirement confined to an extra is left out, as
    optional-dependencies are, while one such as 'x; extra != "y"'
    applies to every install and stays. The marker is dropped once
    decided, so cyclonedx-py has nothing to judge again.
    """
    kept: list[str] = []
    for requirement in requirements:
        try:
            parsed = Requirement(requirement)
        except InvalidRequirement:
            continue
        if parsed.marker is None or parsed.marker.evaluate(environment):
            parsed.marker = None
            kept.append(str(parsed))
    return kept


def installed_requirements(site_packages: str, name: str) -> list[str] | None:
    """Return the requirements an installed distribution records.

    None when the distribution is not installed.
    """
    for dist in distributions(path=[site_packages]):
        if canonical(dist.metadata["Name"] or "") == canonical(name):
            return list(dist.requires or [])
    return None


def is_requirement(item: object) -> bool:
    """Tell whether a value can be passed to pip as one requirement.

    A PEP 508 requirement never holds a NUL or line break, nor starts
    with '-', which pip would read as an option. Anything else is left
    to the build backend to interpret by installing the project.
    """
    return (
        isinstance(item, str)
        and bool(item.strip())
        and not item.lstrip().startswith("-")
        and not any(char in item for char in "\0\r\n")
    )


def report(**fields: str) -> None:
    """Write the result as key=value lines."""
    for key, value in fields.items():
        print(f"{key}={value}")


def load(source: str) -> tuple[Table | None, Table | None, str]:
    """Return the whole document, its [project] table and why not."""
    try:
        with open(source, "rb") as handle:
            data: Table = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, None, f"pyproject.toml could not be read ({type(error).__name__})"
    project = as_table(data.get("project"))
    if project is None or not isinstance(project.get("name"), str):
        return data, None, "pyproject.toml has no PEP 621 [project] table with a name"
    return data, project, ""


def static_dependencies(project: Table) -> list[str] | None:
    """Return the declared dependencies, or None when they are dynamic."""
    dynamic = as_list(project.get("dynamic", []))
    dependencies = as_list(project.get("dependencies", []))
    if (
        dynamic is None
        or "dependencies" in dynamic
        or dependencies is None
        or not all(is_requirement(item) for item in dependencies)
    ):
        return None
    return [str(item).strip() for item in dependencies]


def meets_requires_python(project: Table, version: str) -> bool:
    """Tell whether a Python version meets [project].requires-python.

    An absent field constrains nothing. An unparsable one is the build
    backend's and the package manager's to reject, so it passes here
    rather than this reader inventing a constraint.
    """
    requires_python = project.get("requires-python")
    if not isinstance(requires_python, str):
        return True
    try:
        specifier = SpecifierSet(requires_python)
    except InvalidSpecifier:
        return True
    return specifier.contains(version, prereleases=True)


def inspect(source: str, dependencies_out: str) -> int:
    """Report what the project declares, before anything installs."""
    data, project, reason = load(source)
    groups = as_table(data.get("dependency-groups")) if data is not None else None
    # PEP 735 compares group names as PEP 503 normalises them, so 'Dev'
    # is the group 'pip install --group dev' selects
    dev_group = groups is not None and any(
        canonical(key) == "dev" and as_list(value) is not None
        for key, value in groups.items()
    )
    static = static_dependencies(project) if project is not None else None
    if static is not None:
        with open(dependencies_out, "w", encoding="utf-8") as handle:
            handle.writelines(f"{item}\0" for item in static)
    report(
        project=str(project is not None).lower(),
        reason=reason,
        static_dependencies=str(static is not None).lower(),
        dev_group=str(dev_group).lower(),
    )
    return 0


def anchor(source: str, anchor_out: str, site_packages: str, markers: str) -> int:
    """Write the root component's pyproject.toml for the scan."""
    _, project, reason = load(source)
    if project is None:
        report(anchor="none", reason=reason, compatible="true")
        return 0
    name = str(project["name"])
    environment = marker_environment(markers)
    compatible = meets_requires_python(project, environment["python_full_version"])

    anchored: Table = {
        key: value for key, value in project.items() if key != "optional-dependencies"
    }
    requirements = static_dependencies(project)
    if requirements is None:
        requirements = installed_requirements(site_packages, name)
        if requirements is None:
            reason = "its dependencies are dynamic and the project is not installed"
            requirements = []
        dynamic = as_list(project.get("dynamic", [])) or []
        anchored["dynamic"] = [item for item in dynamic if item != "dependencies"]
    anchored["dependencies"] = applicable(requirements, environment)

    try:
        lines = [
            f"{toml_value(key)} = {toml_value(value)}"
            for key, value in anchored.items()
        ]
    except TypeError as error:
        report(anchor="none", reason=str(error), compatible=str(compatible).lower())
        return 0
    with open(anchor_out, "w", encoding="utf-8") as handle:
        handle.writelines(["[project]\n", *(f"{line}\n" for line in lines)])
    report(anchor="project", reason=reason, compatible=str(compatible).lower())
    return 0
