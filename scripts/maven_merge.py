# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Merge the CycloneDX BOMs a Maven build wrote into one document.

The action's merge mode runs this from the action's own directory as
'-E -s -m scripts.maven_merge', on the interpreter actions/setup-python
installed, so it uses the standard library alone:

  python -m scripts.maven_merge --top <dir> --root-name <name>
    --spec-version <v> --output <json-out> --report <report-out>

maven_discovery finds each module's target/bom.json. The merge keeps
the shape grype-scan-action reads a dependency graph from: one
synthetic root with an empty dependsOn, each module once and unscoped,
each third-party component once at its strongest scope, and every edge.

<spec-version> is 'auto', taking the modules' own specVersion, or one
they must carry. The counts the action reports go to <report-out>.
Every failure prints one '::error::' line and exits 1.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from scripts.maven_discovery import discover, relative, shown, warn

AUTO = "auto"

# The schema versions grype-scan-action's classifier has measured. Grype
# still scans a document outside them, but classifies every finding as
# direct.
MEASURED_SPEC_VERSIONS = ("1.4", "1.5", "1.6")

# 'required', an absent scope (the CycloneDX default) and any value
# CycloneDX does not define all rank 0, the strongest.
STRENGTH = {"optional": 1, "excluded": 2}
SCOPES = ("required", *STRENGTH)


class MergeError(Exception):
    """A reason the merge cannot produce a document."""


def as_list(value: object, name: str, where: str) -> list[object]:
    """Return ``value`` when it is a list, or fail."""
    if not isinstance(value, list):
        raise MergeError(f"{where}: {name} is not a list.")
    return cast("list[object]", value)


def as_object(value: object, name: str, where: str) -> dict[str, object]:
    """Return ``value`` when it is a mapping, or fail."""
    if not isinstance(value, dict):
        raise MergeError(f"{where}: {name} is not an object.")
    return cast("dict[str, object]", value)


def as_ref(value: object, name: str, where: str) -> str:
    """Return ``value`` when it is a non-empty string, or fail."""
    if not isinstance(value, str) or not value:
        raise MergeError(f"{where}: {name} is not a non-empty string.")
    return value


def as_dict(value: object) -> dict[str, object]:
    """Return ``value`` when it is a mapping, else an empty one."""
    if isinstance(value, dict):
        return cast("dict[str, object]", value)
    return {}


@dataclass
class ModuleBom:
    """One module's BOM, checked."""

    path: str
    spec: str
    module: dict[str, object]
    tools: object
    components: list[dict[str, object]]
    edges: list[tuple[str, list[str]]]


def load(path: str, where: str) -> ModuleBom:
    """Read and check the module BOM at ``path``."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = cast("object", json.load(handle))
    except (OSError, RecursionError, ValueError) as error:
        raise MergeError(f"{where} is not a readable JSON document.") from error
    document = as_dict(data)
    if document.get("bomFormat") != "CycloneDX":
        raise MergeError(f"{where} is not a CycloneDX document.")
    spec = document.get("specVersion")
    if not isinstance(spec, str) or not spec:
        raise MergeError(f"{where} does not name its specVersion.")
    metadata = as_dict(document.get("metadata"))
    module = as_dict(metadata.get("component"))
    ref = module.get("bom-ref")
    if not isinstance(ref, str) or not ref:
        raise MergeError(f"{where} does not name its own module.")

    components: list[dict[str, object]] = []
    for raw in as_list(document.get("components", []), "components", where):
        component = as_object(raw, "a components entry", where)
        if "bom-ref" in component:
            _ = as_ref(component["bom-ref"], "a component bom-ref", where)
        components.append(component)
    edges: list[tuple[str, list[str]]] = []
    for raw in as_list(document.get("dependencies", []), "dependencies", where):
        entry = as_object(raw, "a dependencies entry", where)
        source = as_ref(entry.get("ref"), "a dependencies ref", where)
        targets = [
            as_ref(target, "a dependsOn entry", where)
            for target in as_list(entry.get("dependsOn", []), "dependsOn", where)
        ]
        edges.append((source, targets))
    return ModuleBom(path, spec, module, metadata.get("tools"), components, edges)


def coordinates(ref: str) -> str:
    """A Maven purl without its qualifiers and subpath names its module."""
    if ref.startswith("pkg:maven/"):
        return ref.split("#", 1)[0].split("?", 1)[0]
    return ref


def strength(component: dict[str, object]) -> int:
    """Rank a component's scope, 0 being the strongest."""
    scope = component.get("scope")
    return STRENGTH.get(scope, 0) if isinstance(scope, str) else 0


def with_valid_scope(component: dict[str, object]) -> dict[str, object]:
    """Name a third-party component's scope, 'required' unless defined.

    grype-scan-action reads every unscoped component of a reactor
    document as a module, so an absent scope, CycloneDX's 'required',
    is written out. A scope CycloneDX does not define ranks as
    'required' and is written so, keeping the document valid.
    """
    if component.get("scope") in SCOPES:
        return component
    return {**component, "scope": "required"}


def tool_component(tool: object) -> object:
    """Recast a deprecated metadata.tools list entry as a component.

    The fields map as cyclonedx-python-lib maps them between the two
    shapes, the vendor becoming the group.
    """
    if not isinstance(tool, dict):
        return tool
    entry = cast("dict[str, object]", tool)
    component: dict[str, object] = {"type": "application"}
    if "vendor" in entry:
        component["group"] = entry["vendor"]
    component["name"] = entry.get("name", "")
    for key in ("version", "hashes", "externalReferences"):
        if key in entry:
            component[key] = entry[key]
    return component


def wrapped_tools(tools: object) -> dict[str, object]:
    """Return metadata.tools in the 1.5 shape, whichever shape it has."""
    if isinstance(tools, list):
        listed = cast("list[object]", tools)
        return {"components": [tool_component(tool) for tool in listed]}
    return as_dict(tools)


def merge_tools(boms: list[ModuleBom]) -> object:
    """Carry metadata.tools over from every module BOM, once each.

    CycloneDX 1.4 lists tools directly; 1.5 on wraps them in
    'components' and 'services', and still accepts the deprecated list.
    The wrapped shape wins when any BOM carries it, whichever BOM comes
    first, and a list another BOM carries joins it as components, so
    the generator a classifier looks for is never dropped.
    """
    if not any(isinstance(bom.tools, dict) for bom in boms):
        listed: list[object] = []
        for bom in boms:
            if isinstance(bom.tools, list):
                listed.extend(cast("list[object]", bom.tools))
        return unique(listed)
    merged: dict[str, object] = {}
    for bom in boms:
        for key, value in wrapped_tools(bom.tools).items():
            kept = merged.get(key)
            if isinstance(value, list) and isinstance(kept, list):
                joined = [*cast("list[object]", kept), *cast("list[object]", value)]
                merged[key] = unique(joined)
            elif key not in merged:
                merged[key] = cast("object", value)
    return merged


def unique(entries: list[object]) -> list[object]:
    """Drop repeated entries, keeping the first of each."""
    keyed = {json.dumps(entry, sort_keys=True): entry for entry in entries}
    return list(keyed.values())


@dataclass
class Merged:
    """The merged document and what went into it."""

    document: dict[str, object]
    modules: int
    others: int


def merge(boms: list[ModuleBom], root_name: str) -> Merged:
    """Merge checked module BOMs under one synthetic root."""
    # Keyed by coordinates, as the edges are, so two BOMs naming one
    # module by different qualifiers give one module.
    modules: dict[str, dict[str, object]] = {}
    for bom in boms:
        module = {key: value for key, value in bom.module.items() if key != "scope"}
        _ = modules.setdefault(coordinates(cast("str", module["bom-ref"])), module)
    module_of = {key: cast("str", module["bom-ref"]) for key, module in modules.items()}
    module_refs = set(module_of.values())

    def canonical(ref: str) -> str:
        return module_of.get(coordinates(ref), ref)

    third_party: dict[str, dict[str, object]] = {}
    edges: dict[str, dict[str, None]] = {}
    for bom in boms:
        for component in bom.components:
            ref = component.get("bom-ref")
            if isinstance(ref, str):
                key = canonical(ref)
            else:
                # Without scope, so differently scoped copies of one
                # component meet the strongest-scope comparison below.
                unscoped = {k: v for k, v in component.items() if k != "scope"}
                key = json.dumps(unscoped, sort_keys=True)
            if key in module_refs:
                continue
            kept = third_party.get(key)
            if kept is None or strength(component) < strength(kept):
                third_party[key] = with_valid_scope(component)
        for raw_source, targets in bom.edges:
            source = canonical(raw_source)
            joined = edges.setdefault(source, {})
            for raw_target in targets:
                target = canonical(raw_target)
                if target != source:
                    joined[target] = None

    # A purl cannot start 'reactor:', so the root names no module.
    name = root_name or "reactor"
    root = f"reactor:{name}"
    document: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": boms[0].spec,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": merge_tools(boms),
            "component": {"type": "application", "bom-ref": root, "name": name},
        },
        "components": [*modules.values(), *third_party.values()],
        "dependencies": [
            {"ref": root, "dependsOn": []},
            *({"ref": ref, "dependsOn": list(on)} for ref, on in edges.items()),
        ],
    }
    return Merged(document, len(modules), len(third_party))


def resolve_spec(boms: list[ModuleBom], requested: str) -> str:
    """Check the modules share one specVersion and return it."""
    specs = sorted({bom.spec for bom in boms})
    if len(specs) != 1:
        raise MergeError(
            f"The module BOMs mix CycloneDX schemas {', '.join(specs)};"
            + " build every module with one cyclonedx-maven-plugin version."
        )
    spec = specs[0]
    if requested != AUTO and requested != spec:
        raise MergeError(
            f"sbom_spec_version is {requested} but the module BOMs carry"
            + f" CycloneDX {spec}; set sbom_spec_version to 'auto' or {spec}."
        )
    if spec not in MEASURED_SPEC_VERSIONS:
        warn(
            f"The module BOMs carry CycloneDX {spec}, outside the"
            + f" {MEASURED_SPEC_VERSIONS[0]} to {MEASURED_SPEC_VERSIONS[-1]}"
            + " grype-scan-action has measured; Grype scans the document"
            + " but classifies every finding as direct."
        )
    return spec


def run(top: str, root_name: str, requested: str, output: str, report: str) -> None:
    """Merge the module BOMs under ``top``, or raise MergeError."""
    found = discover(top)
    if not found.boms:
        reason = (
            "Merge mode found no target/bom.json beside a pom.xml under"
            + " path_prefix: the build must run cyclonedx-maven-plugin"
            + " makeBom in each module."
        )
        for skipped, why in (
            (found.tracked, "the repository tracks them"),
            (found.linked, "they are behind a symlink"),
        ):
            if skipped:
                reason += f" {len(skipped)} BOMs were skipped because {why}."
        raise MergeError(reason)
    boms = [load(path, relative(path, top)) for path in found.boms]
    spec = resolve_spec(boms, requested)
    merged = merge(boms, root_name)

    with open(output, "w", encoding="utf-8") as handle:
        json.dump(merged.document, handle, indent=2)
        _ = handle.write("\n")
    with open(report, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "spec_version": spec,
                "bom_count": len(found.boms),
                "module_count": merged.modules,
                "other_count": merged.others,
                "skipped_count": len(found.tracked) + len(found.linked),
                "missing_count": len(found.missing),
            },
            handle,
        )

    for path in found.boms:
        print(f"Merged {shown(relative(path, top))}")
    for path in found.missing:
        print(f"No BOM: {shown(relative(path, top))}")
    print(
        f"SBOM: merged {len(found.boms)} module BOMs into {merged.modules}"
        + f" modules and {merged.others} other components; skipped"
        + f" {len(found.tracked)} tracked and {len(found.linked)} linked"
        + f" BOMs; {len(found.missing)} pom.xml directories wrote no BOM."
    )


def main(argv: list[str] | None = None) -> int:
    """Run the merge from the command line."""
    parser = argparse.ArgumentParser(
        description="Merge the CycloneDX BOMs a Maven build wrote."
    )
    _ = parser.add_argument("--top", required=True)
    _ = parser.add_argument("--root-name", default="")
    _ = parser.add_argument("--spec-version", default=AUTO)
    _ = parser.add_argument("--output", required=True)
    _ = parser.add_argument("--report", required=True)
    arguments = parser.parse_args(argv)
    try:
        run(
            cast("str", arguments.top),
            cast("str", arguments.root_name),
            cast("str", arguments.spec_version),
            cast("str", arguments.output),
            cast("str", arguments.report),
        )
    except MergeError as error:
        print(f"::error::{shown(str(error))}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
