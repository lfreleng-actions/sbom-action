# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Unit tests for merge mode's Maven module BOM merge.

Run from the repository root:
python -m unittest discover -s tests/python -t .
"""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import cast
from unittest import mock

from scripts import maven_merge

ROOT_NAME = "example/project"

API = "pkg:maven/org.example/api@1.0.0?type=jar"
IMPL = "pkg:maven/org.example/impl@1.0.0?type=jar"
GUAVA = "pkg:maven/com.google.guava/guava@33.0.0-jre?type=jar"
NETTY = "pkg:maven/io.netty/netty-common@4.2.2.Final?type=jar"

Document = dict[str, object]


def module_bom(
    ref: str,
    components: list[Document],
    edges: dict[str, list[str]],
    spec: str = "1.6",
) -> Document:
    """Return a makeBom-shaped document for the module ``ref``."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "metadata": {
            "tools": {
                "components": [{"type": "library", "name": "cyclonedx-maven-plugin"}]
            },
            "component": {"type": "library", "bom-ref": ref, "name": ref},
        },
        "components": components,
        "dependencies": [
            {"ref": key, "dependsOn": value} for key, value in edges.items()
        ],
    }


def library(ref: str, scope: str | None = "required") -> Document:
    """Return a library component named by ``ref``."""
    component: Document = {"type": "library", "bom-ref": ref, "name": ref}
    if scope is not None:
        component["scope"] = scope
    return component


def place(top: Path, module: str, bom: object) -> None:
    """Write a module at ``top/module`` with ``bom`` as its target BOM."""
    directory = top / module
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pom.xml").touch()
    if bom is not None:
        (directory / "target").mkdir(exist_ok=True)
        text = bom if isinstance(bom, str) else json.dumps(bom)
        _ = (directory / "target" / "bom.json").write_text(text, encoding="utf-8")


def reactor(top: Path) -> None:
    """Lay out a two-module reactor whose impl depends on its api."""
    place(top, ".", None)
    place(top, "api", module_bom(API, [library(GUAVA)], {API: [GUAVA]}))
    place(
        top,
        "impl",
        module_bom(
            IMPL,
            [library(API), library(GUAVA), library(NETTY)],
            {IMPL: [API, NETTY], API: [GUAVA], GUAVA: [], NETTY: []},
        ),
    )


def git(*arguments: str) -> None:
    """Run git quietly, failing the test on an error."""
    _ = subprocess.run(["git", *arguments], check=True, capture_output=True, timeout=30)


class MergeCase(unittest.TestCase):
    """Runs the merge in a scratch tree and reads what it wrote."""

    top: Path = Path()
    out: Path = Path()
    report_path: Path = Path()
    log: str = ""
    status: int = 0

    # typing.override needs Python 3.12; the helper tests run on 3.11 too.
    def setUp(self) -> None:  # pyright: ignore[reportImplicitOverride]
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.top = Path(scratch.name) / "workspace"
        self.top.mkdir()
        self.out = Path(scratch.name) / "sbom.json"
        self.report_path = Path(scratch.name) / "report.json"

    def merge(self, top: Path | None = None, *extra: str) -> int:
        """Run the merge over ``top`` (the workspace by default)."""
        self.out.unlink(missing_ok=True)
        stdout = io.StringIO()
        arguments = [
            "--top",
            str(top or self.top),
            "--root-name",
            ROOT_NAME,
            "--output",
            str(self.out),
            "--report",
            str(self.report_path),
            *extra,
        ]
        with redirect_stdout(stdout):
            self.status = maven_merge.main(arguments)
        self.log = stdout.getvalue()
        return self.status

    def assert_passes(self) -> None:
        self.assertEqual(self.status, 0, self.log)
        self.assertNotIn("::error::", self.log)

    def assert_fails(self) -> None:
        self.assertEqual(self.status, 1, self.log)
        self.assertIn("::error::", self.log)
        self.assertFalse(self.out.exists(), "a failed merge writes nothing")

    def merged(self) -> Document:
        return cast("Document", json.loads(self.out.read_text("utf-8")))

    def report(self) -> Document:
        return cast("Document", json.loads(self.report_path.read_text("utf-8")))

    def components(self) -> list[Document]:
        return cast("list[Document]", self.merged()["components"])

    def refs(self) -> list[str]:
        return sorted(cast("str", c["bom-ref"]) for c in self.components())

    def scopes(self) -> dict[str, object]:
        return {cast("str", c["bom-ref"]): c.get("scope") for c in self.components()}

    def edges(self) -> dict[str, list[str]]:
        entries = cast("list[Document]", self.merged()["dependencies"])
        return {
            cast("str", entry["ref"]): cast("list[str]", entry["dependsOn"])
            for entry in entries
        }


class SbomMerge(MergeCase):
    """The cases carried over from java-workflows' merge step."""

    def test_merges_the_modules_into_one_graph(self) -> None:
        """Each module once and unscoped, each library once, edges joined."""
        reactor(self.top)

        _ = self.merge()

        self.assert_passes()
        document = self.merged()
        root = f"reactor:{ROOT_NAME}"
        self.assertEqual(document["specVersion"], "1.6")
        metadata = cast("Document", document["metadata"])
        self.assertEqual(cast("Document", metadata["component"])["bom-ref"], root)
        self.assertEqual(self.refs(), sorted([API, IMPL, GUAVA, NETTY]))
        self.assertIsNone(self.scopes()[API], "a sibling stays a module")
        self.assertEqual(self.scopes()[GUAVA], "required")
        edges = self.edges()
        self.assertEqual(edges[root], [])
        self.assertEqual(edges[IMPL], [API, NETTY])
        self.assertEqual(edges[API], [GUAVA])

    def test_a_bundle_module_stays_one_module(self) -> None:
        """A sibling's ?type=jar names the ?type=bundle module once."""
        bundle = API.replace("type=jar", "type=bundle")
        place(self.top, "api", module_bom(bundle, [library(GUAVA)], {}))
        place(
            self.top,
            "impl",
            module_bom(
                IMPL,
                [library(API), library(GUAVA)],
                {IMPL: [API], API: [GUAVA], GUAVA: []},
            ),
        )

        _ = self.merge()

        self.assert_passes()
        self.assertEqual(self.refs(), sorted([bundle, IMPL, GUAVA]))
        edges = self.edges()
        self.assertNotIn(API, edges)
        self.assertEqual(edges[IMPL], [bundle])
        self.assertEqual(edges[bundle], [GUAVA])

    def test_the_strongest_scope_wins(self) -> None:
        """A library two modules scope differently keeps the stronger.

        An absent scope is CycloneDX's default, 'required', and so is a
        value CycloneDX does not define; the merge writes both as
        'required', so the document stays valid and only modules go
        unscoped.
        """
        cases = (
            ("optional", "required", "required"),
            ("required", "optional", "required"),
            ("excluded", "optional", "optional"),
            ("optional", None, "required"),
            ("excluded", None, "required"),
            (None, None, "required"),
            ("optional", "mandatory", "required"),
            ("mandatory", None, "required"),
        )
        for first, second, expected in cases:
            with self.subTest(first=first, second=second):
                for child in ("a", "b"):
                    path = self.top / child / "target" / "bom.json"
                    path.unlink(missing_ok=True)
                place(self.top, "a", module_bom(API, [library(GUAVA, first)], {}))
                place(self.top, "b", module_bom(IMPL, [library(GUAVA, second)], {}))

                _ = self.merge()

                self.assert_passes()
                self.assertEqual(self.scopes()[GUAVA], expected)

    def test_a_component_without_a_ref_keeps_its_strongest_scope(self) -> None:
        """Copies of a ref-less component differing in scope merge."""
        anonymous: Document = {"type": "library", "name": "vendored"}
        place(self.top, "a", module_bom(API, [{**anonymous, "scope": "optional"}], {}))
        place(self.top, "b", module_bom(IMPL, [anonymous], {}))

        _ = self.merge()

        self.assert_passes()
        others = [c for c in self.components() if "bom-ref" not in c]
        self.assertEqual(others, [{**anonymous, "scope": "required"}])
        self.assertEqual(self.report()["other_count"], 1)

    def test_only_modules_go_unscoped(self) -> None:
        """A library no module scopes is not read as a module.

        grype-scan-action takes every unscoped component of a reactor
        document for a module, so for api -> netty (unscoped) -> guava
        an unscoped netty would make guava a direct dependency.
        """
        place(
            self.top,
            "api",
            module_bom(
                API,
                [library(NETTY, None), library(GUAVA)],
                {API: [NETTY], NETTY: [GUAVA], GUAVA: []},
            ),
        )

        _ = self.merge()

        self.assert_passes()
        unscoped = [ref for ref, scope in self.scopes().items() if scope is None]
        self.assertEqual(unscoped, [API])
        self.assertEqual(self.scopes()[NETTY], "required")

    def test_skips_a_bom_the_repository_tracks(self) -> None:
        """A committed target/bom.json is not the build's output."""
        reactor(self.top)
        place(self.top, "archived/old", module_bom(NETTY, [], {NETTY: []}))
        git("init", "-q", str(self.top))
        git("-C", str(self.top), "add", "archived/old")

        _ = self.merge()

        self.assert_passes()
        self.assertEqual(self.refs(), sorted([API, IMPL, GUAVA, NETTY]))
        self.assertEqual(self.scopes()[NETTY], "required", "not a module")
        self.assertIn("archived/old/target/bom.json", self.log)
        self.assertNotIn("Merged archived", self.log)
        self.assertEqual(self.report()["skipped_count"], 1)

    def test_skips_a_bom_a_nested_repository_tracks(self) -> None:
        """A BOM committed in a submodule is not the build's output."""
        reactor(self.top)
        place(self.top, "lib/old", module_bom(NETTY, [], {NETTY: []}))
        for repo in (self.top, self.top / "lib"):
            git("init", "-q", str(repo))
        git("-C", str(self.top / "lib"), "add", "old")

        _ = self.merge()

        self.assert_passes()
        self.assertIn("lib/old/target/bom.json", self.log)
        self.assertNotIn("Merged lib", self.log)

    def test_an_attached_artifact_is_its_module(self) -> None:
        """A dependency on an artefact api attached names api itself."""
        for attached in (
            API.replace("?type=jar", "?classifier=tests&type=jar"),
            API.replace("?type=jar", "?classifier=config&type=cfg"),
        ):
            with self.subTest(attached=attached):
                place(self.top, "api", module_bom(API, [library(GUAVA)], {}))
                place(
                    self.top,
                    "impl",
                    module_bom(
                        IMPL,
                        [library(attached), library(GUAVA)],
                        {IMPL: [attached], attached: [GUAVA], GUAVA: []},
                    ),
                )

                _ = self.merge()

                self.assert_passes()
                self.assertEqual(self.refs(), sorted([API, IMPL, GUAVA]))
                edges = self.edges()
                self.assertEqual(edges[IMPL], [API])
                self.assertEqual(edges[API], [GUAVA])

    def test_fails_on_a_module_without_a_name(self) -> None:
        """A module BOM must name itself by a nonempty bom-ref."""
        for ref in (None, "", 7):
            with self.subTest(ref=ref):
                bom = module_bom(API, [], {API: []})
                component = cast(
                    "Document", cast("Document", bom["metadata"])["component"]
                )
                if ref is None:
                    del component["bom-ref"]
                else:
                    component["bom-ref"] = ref
                place(self.top, "api", bom)

                _ = self.merge()

                self.assert_fails()
                self.assertIn("api/target/bom.json", self.log)

    def test_ignores_boms_outside_the_modules(self) -> None:
        """A BOM in a target tree or beside no pom.xml is not a module."""
        reactor(self.top)
        bogus = json.dumps({"bomFormat": "bogus"})
        place(self.top, "impl/target/it/sample", bogus)
        stray = self.top / "docs/target"
        stray.mkdir(parents=True)
        _ = (stray / "bom.json").write_text(bogus, encoding="utf-8")

        _ = self.merge()

        self.assert_passes()
        self.assertNotIn("sample", self.log)
        self.assertNotIn("docs", self.log)

    def test_walks_from_the_path_prefix(self) -> None:
        """The walk covers path_prefix: '.' reaches modules beside a root."""
        place(self.top, "reactor", module_bom(API, [], {API: []}))
        place(self.top, "core", module_bom(IMPL, [], {IMPL: [API]}))

        _ = self.merge(self.top / "reactor")

        self.assert_passes()
        self.assertEqual(self.refs(), [API], "core lies outside the prefix")

        _ = self.merge(self.top)

        self.assert_passes()
        self.assertEqual(self.refs(), sorted([API, IMPL]))

    def test_names_the_root_by_merge_root_name(self) -> None:
        """The root names the repository the caller passes."""
        reactor(self.top)

        _ = self.merge()

        self.assert_passes()
        metadata = cast("Document", self.merged()["metadata"])
        self.assertEqual(
            metadata["component"],
            {
                "type": "application",
                "bom-ref": f"reactor:{ROOT_NAME}",
                "name": ROOT_NAME,
            },
        )

    def test_fails_without_a_module_bom(self) -> None:
        """A build that wrote no module BOM leaves nothing to scan."""
        place(self.top, ".", None)

        _ = self.merge()

        self.assert_fails()
        self.assertIn("makeBom", self.log)

    def test_fails_on_mixed_schemas(self) -> None:
        """Module BOMs of two specVersions do not merge into one."""
        reactor(self.top)
        place(self.top, "old", module_bom(NETTY, [], {}, spec="1.4"))

        _ = self.merge()

        self.assert_fails()
        self.assertIn("1.4, 1.6", self.log)

    def test_fails_without_a_schema_version(self) -> None:
        """A module BOM must name its specVersion as a string."""
        for spec in (None, "", 1.6):
            with self.subTest(spec=spec):
                bom = module_bom(API, [], {API: []})
                if spec is None:
                    del bom["specVersion"]
                else:
                    bom["specVersion"] = spec
                place(self.top, "api", bom)

                _ = self.merge()

                self.assert_fails()

    def test_fails_on_a_document_that_is_not_cyclonedx(self) -> None:
        """A module's target/bom.json that is not CycloneDX fails."""
        reactor(self.top)
        place(self.top, "odd", {"bomFormat": "SPDX"})

        _ = self.merge()

        self.assert_fails()
        self.assertIn("odd/target/bom.json is not a CycloneDX document", self.log)


class SbomMergeContract(MergeCase):
    """Behaviour merge mode adds beyond the java-workflows step."""

    def test_fails_on_a_document_that_is_not_json(self) -> None:
        """A module BOM that does not parse fails, naming the file."""
        place(self.top, "api", "{not json")

        _ = self.merge()

        self.assert_fails()
        self.assertIn("api/target/bom.json is not a readable JSON document", self.log)

    def test_fails_on_a_wrongly_typed_list(self) -> None:
        """A list of the wrong type fails with an error, not a traceback."""
        for name, value in (
            ("components", 7),
            ("dependencies", "x"),
            ("dependsOn", {"a": 1}),
            ("components", None),
            ("dependencies", None),
            ("dependsOn", None),
        ):
            with self.subTest(name=name, value=value):
                bom = module_bom(API, [], {API: []})
                if name == "dependsOn":
                    bom["dependencies"] = [{"ref": API, "dependsOn": value}]
                else:
                    bom[name] = value
                place(self.top, "api", bom)

                _ = self.merge()

                self.assert_fails()
                self.assertIn(f"api/target/bom.json: {name} is not a list", self.log)

    def test_fails_on_a_malformed_list_member(self) -> None:
        """A malformed entry fails the merge instead of going missing."""
        cases: list[tuple[str, list[object], str]] = [
            ("components", [None], "a components entry is not an object"),
            ("components", [{"bom-ref": 7}], "a component bom-ref is not"),
            ("dependencies", [None], "a dependencies entry is not an object"),
            ("dependencies", [{"dependsOn": []}], "a dependencies ref is not"),
            ("dependencies", [{"ref": 7}], "a dependencies ref is not"),
            ("dependencies", [{"ref": API, "dependsOn": [7]}], "a dependsOn entry"),
            ("dependencies", [{"ref": API, "dependsOn": [""]}], "a dependsOn entry"),
        ]
        for field, value, error in cases:
            with self.subTest(field=field, value=value):
                bom = module_bom(API, [], {API: []})
                bom[field] = value
                place(self.top, "api", bom)

                _ = self.merge()

                self.assert_fails()
                self.assertIn(f"api/target/bom.json: {error}", self.log)

    def test_names_a_tracked_bom_as_untrusted(self) -> None:
        """The warning says the BOM is tracked, not that no build wrote it."""
        place(self.top, "api", module_bom(API, [], {API: []}))
        git("init", "-q", str(self.top))
        git("-C", str(self.top), "add", "api")

        _ = self.merge()

        self.assert_fails()
        self.assertIn("::warning::Skipped api/target/bom.json", self.log)
        self.assertIn("not trusted as this build's output", self.log)
        self.assertNotIn("did not write", self.log)
        self.assertIn(
            "1 BOMs were skipped because the repository tracks them", self.log
        )

    def test_skips_a_bom_behind_a_symbolic_link(self) -> None:
        """A linked target or BOM could pass off a tracked or outside file."""
        outside = self.top.parent / "outside"
        outside.mkdir()
        _ = (outside / "bom.json").write_text(
            json.dumps(module_bom(NETTY, [], {})), encoding="utf-8"
        )
        place(self.top, "api", module_bom(API, [], {API: []}))
        place(self.top, "linked-target", None)
        (self.top / "linked-target" / "target").symlink_to(outside)
        place(self.top, "linked-bom", None)
        (self.top / "linked-bom" / "target").mkdir()
        (self.top / "linked-bom" / "target" / "bom.json").symlink_to(
            outside / "bom.json"
        )

        _ = self.merge()

        self.assert_passes()
        self.assertNotIn(NETTY, self.refs())
        for module in ("linked-target", "linked-bom"):
            self.assertIn(
                f"::warning::Skipped {module}/target/bom.json: it is behind a symlink",
                self.log,
            )
        self.assertEqual(self.report()["skipped_count"], 2)
        self.assertEqual(self.report()["bom_count"], 1)

    def test_warns_when_git_cannot_answer(self) -> None:
        """A module whose tracked state is unknown merges with a warning."""
        (self.top / ".git").mkdir()
        place(self.top, "api", module_bom(API, [], {API: []}))

        with mock.patch(
            "scripts.maven_discovery.subprocess.run",
            side_effect=FileNotFoundError("git"),
        ):
            _ = self.merge()

        self.assert_passes()
        self.assertIn("::warning::Could not ask git", self.log)
        self.assertIn("Merged api/target/bom.json", self.log)

    def test_prunes_invoker_projects(self) -> None:
        """A project maven-invoker-plugin ran under src/it is no module."""
        reactor(self.top)
        place(self.top, "impl/src/it/sample", module_bom(NETTY, [], {}))

        _ = self.merge()

        self.assert_passes()
        self.assertNotIn("sample", self.log)
        self.assertEqual(self.report()["module_count"], 2)

    def test_a_workspace_maven_repository_yields_no_module(self) -> None:
        """An m2repo inside the workspace holds *.pom files, never pom.xml."""
        reactor(self.top)
        cached = self.top / "m2repo/io/netty/netty-common/4.2.2.Final"
        cached.mkdir(parents=True)
        (cached / "netty-common-4.2.2.Final.pom").touch()
        (cached / "netty-common-4.2.2.Final.jar").touch()

        _ = self.merge()

        self.assert_passes()
        self.assertNotIn("m2repo", self.log)
        self.assertEqual(self.report()["missing_count"], 1, "the root alone")

    def test_reports_the_counts(self) -> None:
        """The report and the log line count BOMs, modules and gaps."""
        reactor(self.top)
        place(self.top, "nobom", None)

        _ = self.merge()

        self.assert_passes()
        self.assertEqual(
            self.report(),
            {
                "spec_version": "1.6",
                "bom_count": 2,
                "module_count": 2,
                "other_count": 2,
                "skipped_count": 0,
                "missing_count": 2,
            },
        )
        self.assertIn("No BOM: nobom", self.log)
        self.assertIn(
            "merged 2 module BOMs into 2 modules and 2 other components", self.log
        )

    def test_carries_the_tools_over(self) -> None:
        """grype-scan-action classifies only a generator it has measured."""
        for spec, tools in (
            (
                "1.6",
                {"components": [{"type": "library", "name": "cyclonedx-maven-plugin"}]},
            ),
            ("1.4", [{"vendor": "OWASP", "name": "CycloneDX Maven plugin"}]),
        ):
            with self.subTest(spec=spec):
                for module, ref in (("api", API), ("impl", IMPL)):
                    bom = module_bom(ref, [], {}, spec=spec)
                    cast("Document", bom["metadata"])["tools"] = tools
                    place(self.top, module, bom)

                _ = self.merge()

                self.assert_passes()
                document = self.merged()
                self.assertEqual(document["specVersion"], spec)
                metadata = cast("Document", document["metadata"])
                self.assertEqual(metadata["tools"], tools, "once, not twice")

    def test_keeps_wrapped_tools_a_later_bom_carries(self) -> None:
        """A first BOM without tools does not drop a later BOM's."""
        tools = {"components": [{"type": "library", "name": "cyclonedx-maven-plugin"}]}
        first = module_bom(API, [], {})
        del cast("Document", first["metadata"])["tools"]
        place(self.top, "a", first)
        place(self.top, "b", module_bom(IMPL, [], {}))

        _ = self.merge()

        self.assert_passes()
        metadata = cast("Document", self.merged()["metadata"])
        self.assertEqual(metadata["tools"], tools)

    def test_joins_listed_tools_to_wrapped_ones(self) -> None:
        """A deprecated tools list beside the wrapped shape is kept."""
        listed = module_bom(API, [], {})
        cast("Document", listed["metadata"])["tools"] = [
            {"vendor": "OWASP", "name": "cyclonedx-maven-plugin", "version": "2.9.1"}
        ]
        services = module_bom(IMPL, [], {})
        cast("Document", services["metadata"])["tools"] = {
            "services": [{"name": "builder"}]
        }
        place(self.top, "a", listed)
        place(self.top, "b", services)

        _ = self.merge()

        self.assert_passes()
        metadata = cast("Document", self.merged()["metadata"])
        self.assertEqual(
            metadata["tools"],
            {
                "components": [
                    {
                        "type": "application",
                        "group": "OWASP",
                        "name": "cyclonedx-maven-plugin",
                        "version": "2.9.1",
                    }
                ],
                "services": [{"name": "builder"}],
            },
        )

    def test_one_module_named_by_two_qualifiers_stays_one(self) -> None:
        """Two BOMs of one module's coordinates give one module entry."""
        bundle = API.replace("type=jar", "type=bundle")
        place(self.top, "a", module_bom(API, [library(GUAVA)], {API: [GUAVA]}))
        place(self.top, "b", module_bom(bundle, [library(NETTY)], {bundle: [NETTY]}))

        _ = self.merge()

        self.assert_passes()
        self.assertEqual(self.refs(), sorted([API, GUAVA, NETTY]))
        self.assertEqual(self.report()["module_count"], 1)
        self.assertEqual(self.edges()[API], [GUAVA, NETTY])

    def test_an_explicit_spec_version_is_an_assertion(self) -> None:
        """An explicit sbom_spec_version must match the modules' own."""
        reactor(self.top)

        _ = self.merge(None, "--spec-version", "1.6")
        self.assert_passes()

        _ = self.merge(None, "--spec-version", "1.5")
        self.assert_fails()
        self.assertIn("sbom_spec_version is 1.5", self.log)
        self.assertIn("carry CycloneDX 1.6", self.log)

    def test_warns_outside_the_measured_range(self) -> None:
        """A version grype-scan-action has not measured still merges."""
        for spec, warned in (
            ("1.3", True),
            ("1.4", False),
            ("1.6", False),
            ("1.7", True),
        ):
            with self.subTest(spec=spec):
                place(self.top, "api", module_bom(API, [], {}, spec=spec))

                _ = self.merge()

                self.assert_passes()
                self.assertEqual("::warning::" in self.log, warned, self.log)


if __name__ == "__main__":
    _ = unittest.main()
