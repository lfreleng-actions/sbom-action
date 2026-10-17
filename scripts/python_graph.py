# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Finish the python backend's SBOM.

cyclonedx-py turns every requirement of every installed distribution
into a dependency edge, by name, whatever its marker says: pluggy's
'pytest; extra == "testing"' links pluggy to pytest wherever pytest is
installed (measured on cyclonedx-bom 7.5.0). The finished document
instead carries an edge where the requirement's marker holds for the
scanned interpreter with the extras actually requested, the project's
own edges included, and both formats come from that one document,
checked against the CycloneDX schema before either is written.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from importlib.metadata import distributions
from typing import NamedTuple, cast

# Both ship with cyclonedx-bom, whose environment runs this script.
# cyclonedx-python-lib is checked against the stubs under typings/,
# without its source: see the basedpyright hook in .pre-commit-config.yaml.
# pyright: reportMissingModuleSource=false
from cyclonedx.model.bom import Bom
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator
from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement

from scripts.python_pyproject import (
    Table,
    as_list,
    as_table,
    canonical,
    load,
    marker_environment,
    static_dependencies,
)


class Documents(NamedTuple):
    """The files finish reads and writes."""

    scanned: str
    site_packages: str
    markers: str
    spec_version: str
    pyproject: str
    json_out: str
    xml_out: str | None


# cyclonedx-py's name for the extras a component is required with
REQUIRED_EXTRA = "cdx:python:package:required-extra"


def parse_requirements(texts: list[str]) -> list[Requirement]:
    """Parse requirement strings, skipping any that do not parse."""
    parsed: list[Requirement] = []
    for text in texts:
        try:
            parsed.append(Requirement(text))
        except InvalidRequirement:
            continue
    return parsed


def project_requirements(project: Table) -> list[Requirement]:
    """Return a project's requirements as its metadata would record them.

    Optional dependencies become requirements of their extra, as a
    build backend writes them into Requires-Dist, so the project's own
    extras resolve like anyone else's. The marker is attached as an
    object rather than appended to the text, which would need the
    whitespace PEP 508 requires before a direct URL's marker.
    """
    found = parse_requirements(list(static_dependencies(project) or []))
    groups = as_table(project.get("optional-dependencies")) or {}
    for group, items in groups.items():
        for requirement in parse_requirements(
            [str(item) for item in as_list(items) or []]
        ):
            condition = f'extra == "{canonical(group)}"'
            if requirement.marker is not None:
                condition = f"({requirement.marker}) and {condition}"
            requirement.marker = Marker(condition)
            found.append(requirement)
    return found


class Resolution:
    """Which requirements apply, and with which extras.

    A requirement applies when its marker holds for no extra or for one
    requested of the distribution that declares it. Extras follow the
    requirements that apply, a distribution's own included: a 'bundle'
    whose 'all' extra requires 'bundle[http]' requests 'http' of itself.
    The project is one more distribution here, installed or not, since
    cyclonedx-py points any requirement naming it at the root.
    """

    def __init__(
        self, requirements: dict[str, list[Requirement]], environment: dict[str, str]
    ) -> None:
        """Start with no edges, no extras and nothing reached at runtime."""
        self.requirements: dict[str, list[Requirement]] = requirements
        self.environment: dict[str, str] = environment
        self.extras: dict[str, set[str]] = {name: set() for name in requirements}
        self.edges: dict[str, set[str]] = {name: set() for name in requirements}
        self.runtime: set[str] = set()

    def applying(self, name: str) -> list[tuple[str, set[str]]]:
        """Return each known target of name that applies, with extras."""
        selected = ["", *sorted(self.extras[name])]
        found: list[tuple[str, set[str]]] = []
        for requirement in self.requirements[name]:
            target = canonical(requirement.name)
            marker = requirement.marker
            if target not in self.requirements or (
                marker is not None
                and not any(
                    marker.evaluate({**self.environment, "extra": extra})
                    for extra in selected
                )
            ):
                continue
            found.append((target, {canonical(item) for item in requirement.extras}))
        return found

    def follow(self, names: list[str], runtime: bool) -> bool:
        """Follow the requirements of names once; tell whether anything grew.

        Following from the runtime set, each target joins it and takes
        the extras requested. Following from everything else, a target
        already reached at runtime gains the edge but no extras: a
        development tool requiring requests[socks] does not make PySocks
        a runtime dependency of requests.
        """
        grew = False
        for name in names:
            for target, wanted in self.applying(name):
                if target != name:
                    self.edges[name].add(target)
                if runtime and target not in self.runtime:
                    self.runtime.add(target)
                    grew = True
                if (runtime or target not in self.runtime) and not (
                    wanted <= self.extras[target]
                ):
                    self.extras[target] |= wanted
                    grew = True
        return grew


def resolve_graph(
    requirements: dict[str, list[Requirement]],
    environment: dict[str, str],
    root: str | None,
) -> Resolution:
    """Resolve the edges that apply and the extras requested of each.

    Two passes, each to a fixed point. The first follows the runtime
    graph from the project. The second follows everything else,
    development dependencies and anything without a project, so their
    own edges stay without their extras reaching the runtime graph.
    """
    resolution = Resolution(requirements, environment)
    if root is not None:
        resolution.runtime.add(root)
    while resolution.follow(sorted(resolution.runtime), runtime=True):
        pass
    rest = sorted(set(requirements) - resolution.runtime)
    while resolution.follow(rest, runtime=False):
        pass
    return resolution


def resolve(documents: Documents) -> Resolution:
    """Resolve the scanned environment's graph, the project included."""
    requirements: dict[str, list[Requirement]] = {}
    for dist in distributions(path=[documents.site_packages]):
        name = canonical(dist.metadata["Name"] or "")
        requirements[name] = parse_requirements(list(dist.requires or []))

    root = None
    if documents.pyproject != "-":
        _, project, _ = load(documents.pyproject)
        if project is not None:
            root = canonical(str(project["name"]))
            # An installed project's metadata is authoritative; it is
            # where a build backend recorded dynamic dependencies
            if root not in requirements:
                requirements[root] = project_requirements(project)

    return resolve_graph(requirements, marker_environment(documents.markers), root)


def properties_supported(spec_version: str) -> bool:
    """Tell whether a CycloneDX version has component properties (1.3+)."""
    return tuple(int(part) for part in spec_version.split(".")) >= (1, 3)


def set_required_extras(component: Table, extras: set[str]) -> None:
    """Make a component's required-extra properties name these extras."""
    properties = [
        prop
        for prop in as_list(component.get("properties")) or []
        if (as_table(prop) or {}).get("name") != REQUIRED_EXTRA
    ]
    properties += [{"name": REQUIRED_EXTRA, "value": extra} for extra in sorted(extras)]
    if properties:
        component["properties"] = properties
    else:
        _ = component.pop("properties", None)


def rewrite(document: Table, resolution: Resolution, spec_version: str) -> int:
    """Give every known component the edges that apply; count changes.

    A component the resolution cannot account for keeps what
    cyclonedx-py gave it, since nothing is known about it.
    """
    metadata = as_table(document.get("metadata"))
    components = [
        component
        for component in [as_table(metadata.get("component")) if metadata else None]
        + [as_table(item) for item in as_list(document.get("components")) or []]
        if component is not None
    ]
    names: dict[str, str] = {}
    for component in components:
        ref, name = component.get("bom-ref"), component.get("name")
        if not isinstance(ref, str) or not isinstance(name, str):
            continue
        names[ref] = canonical(name)
        if properties_supported(spec_version) and names[ref] in resolution.extras:
            set_required_extras(component, resolution.extras[names[ref]])
    refs = {name: ref for ref, name in names.items()}

    changed = 0
    for item in as_list(document.get("dependencies")) or []:
        entry = as_table(item)
        ref = entry.get("ref") if entry is not None else None
        name = names.get(ref) if isinstance(ref, str) else None
        if entry is None or name is None or name not in resolution.edges:
            continue
        before = {str(target) for target in as_list(entry.get("dependsOn")) or []}
        after = sorted(
            refs[target] for target in resolution.edges[name] if target in refs
        )
        changed += len(before.symmetric_difference(after))
        if after:
            entry["dependsOn"] = after
        else:
            _ = entry.pop("dependsOn", None)
    return changed


def write_atomically(path: str, text: str) -> None:
    """Write a file beside its destination, then move it into place."""
    handle, temporary = tempfile.mkstemp(
        dir=os.path.dirname(path) or ".", prefix=".sbom-"
    )
    with os.fdopen(handle, "w", encoding="utf-8") as output:
        _ = output.write(text)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def finish(documents: Documents) -> int:
    """Write the finished document in the formats requested."""
    with open(documents.scanned, encoding="utf-8") as handle:
        document = as_table(cast("object", json.load(handle)))
    if document is None:
        print("The scanned document is not a JSON object", file=sys.stderr)
        return 1
    changed = rewrite(document, resolve(documents), documents.spec_version)
    print(f"Dependency edges changed to follow the requirements: {changed}")

    version = SchemaVersion.from_version(documents.spec_version)
    outputs = [(OutputFormat.JSON, documents.json_out, json.dumps(document, indent=2))]
    if documents.xml_out is not None:
        bom = Bom.from_json(document)
        if bom is None:
            print("The JSON document does not read as a BOM", file=sys.stderr)
            return 1
        xml = make_outputter(bom, OutputFormat.XML, version).output_as_string(indent=2)
        outputs.append((OutputFormat.XML, documents.xml_out, xml))
    # cyclonedx-py validates what it writes; the rewritten document has
    # to meet the same schema before either format is published
    for output_format, _, text in outputs:
        error = make_schemabased_validator(output_format, version).validate_str(text)
        if error is not None:
            schema = f"CycloneDX {documents.spec_version}"
            print(
                f"The {output_format.name} document fails the {schema} schema: {error}",
                file=sys.stderr,
            )
            return 1
    for _, path, text in outputs:
        write_atomically(path, text + ("" if text.endswith("\n") else "\n"))
    return 0
