# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Unit tests for the python backend's dependency-graph helpers.

Run from the repository root, in an environment holding cyclonedx-bom:
python -m unittest discover -s tests/python -t .
"""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement

from scripts.python_graph import (
    parse_requirements,
    project_requirements,
    properties_supported,
    resolve_graph,
)
from scripts.python_pyproject import inspect, toml_value

if sys.version_info >= (3, 11):  # noqa: UP036
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # pyright: ignore[reportUnreachable]

# The interpreter running the tests stands in for the scanned one
ENVIRONMENT = {key: str(value) for key, value in default_environment().items()}


def requires(*texts: str) -> list[Requirement]:
    """Parse requirement strings for a fixture graph."""
    return parse_requirements(list(texts))


class ProjectRequirementsTest(unittest.TestCase):
    """Optional dependencies become requirements of their extra."""

    def test_direct_url_optional_dependency_survives(self) -> None:
        """A URL requirement keeps its URL and gains the extra marker."""
        project: dict[str, object] = {
            "name": "app",
            "dependencies": ["iniconfig==2.1.0"],
            "optional-dependencies": {
                "Feature": ["transport @ file:///srv/transport"],
            },
        }
        found = {item.name: item for item in project_requirements(project)}
        self.assertEqual(set(found), {"iniconfig", "transport"})
        transport = found["transport"]
        self.assertEqual(transport.url, "file:///srv/transport")
        self.assertIsNotNone(transport.marker)
        marker = transport.marker
        assert marker is not None
        self.assertTrue(marker.evaluate({**ENVIRONMENT, "extra": "feature"}))
        self.assertFalse(marker.evaluate({**ENVIRONMENT, "extra": ""}))
        # Round-trips through text, as a requirement written out would
        self.assertEqual(Requirement(str(transport)).url, transport.url)

    def test_existing_marker_combines_with_the_extra(self) -> None:
        """A requirement's own marker still has to hold."""
        project: dict[str, object] = {
            "name": "app",
            "optional-dependencies": {"x": ['six; python_version < "3"']},
        }
        (six,) = project_requirements(project)
        marker = six.marker
        assert marker is not None
        self.assertFalse(marker.evaluate({**ENVIRONMENT, "extra": "x"}))


class ResolveGraphTest(unittest.TestCase):
    """Edges follow the requirements that apply, with requested extras."""

    def test_extra_requested_of_an_uninstalled_project(self) -> None:
        """A runtime dependency's request reaches the project's edges."""
        project: dict[str, object] = {
            "name": "app",
            "dependencies": ["plugin"],
            "optional-dependencies": {
                "feature": ["transport[socks] @ file:///srv/transport"],
            },
        }
        graph = {
            "app": project_requirements(project),
            "plugin": requires("app[feature]"),
            "transport": requires('iniconfig; extra == "socks"'),
            "iniconfig": [],
        }
        resolution = resolve_graph(graph, ENVIRONMENT, "app")
        self.assertEqual(resolution.edges["app"], {"plugin", "transport"})
        self.assertEqual(resolution.edges["plugin"], {"app"})
        self.assertEqual(resolution.edges["transport"], {"iniconfig"})
        self.assertEqual(resolution.extras["app"], {"feature"})

    def test_inactive_extra_requirement_is_no_edge(self) -> None:
        """pluggy's testing extra does not make it depend on pytest."""
        graph = {
            "app": requires("pluggy"),
            "pluggy": requires('pytest; extra == "testing"'),
            "pytest": requires("pluggy"),
        }
        resolution = resolve_graph(graph, ENVIRONMENT, "app")
        self.assertEqual(resolution.edges["pluggy"], set())
        self.assertEqual(resolution.edges["pytest"], {"pluggy"})

    def test_self_requested_extra(self) -> None:
        """An extra naming its own distribution's extra counts."""
        graph = {
            "app": requires("bundle[all]"),
            "bundle": requires(
                'bundle[http]; extra == "all"', 'transport; extra == "http"'
            ),
            "transport": [],
        }
        resolution = resolve_graph(graph, ENVIRONMENT, "app")
        self.assertEqual(resolution.edges["bundle"], {"transport"})
        self.assertEqual(resolution.extras["bundle"], {"all", "http"})

    def test_development_extras_stay_off_the_runtime_graph(self) -> None:
        """A dev tool requesting requests[socks] changes no runtime edge."""
        graph = {
            "app": requires("requests"),
            "requests": requires('pysocks; extra == "socks"'),
            "pysocks": [],
            "devtool": requires("requests[socks]"),
        }
        resolution = resolve_graph(graph, ENVIRONMENT, "app")
        self.assertEqual(resolution.edges["requests"], set())
        self.assertEqual(resolution.extras["requests"], set())
        self.assertEqual(resolution.edges["devtool"], {"requests"})

    def test_markers_judged_against_the_given_environment(self) -> None:
        """implementation_version decides, as reported."""
        graph = {
            "app": requires(
                "new; implementation_version >= '3.13'",
                "old; implementation_version < '3.13'",
            ),
            "new": [],
            "old": [],
        }
        on_313 = {**ENVIRONMENT, "implementation_version": "3.13.0"}
        self.assertEqual(resolve_graph(graph, on_313, "app").edges["app"], {"new"})
        on_312 = {**ENVIRONMENT, "implementation_version": "3.12.9"}
        self.assertEqual(resolve_graph(graph, on_312, "app").edges["app"], {"old"})


class SchemaTest(unittest.TestCase):
    """Component properties exist from CycloneDX 1.3."""

    def test_properties_supported(self) -> None:
        """1.2 has none; 1.3 onwards does."""
        self.assertFalse(properties_supported("1.2"))
        self.assertTrue(properties_supported("1.3"))
        self.assertTrue(properties_supported("1.10"))


class PyprojectTest(unittest.TestCase):
    """The reader's TOML output and its report."""

    def test_toml_value_round_trips(self) -> None:
        """Rendered values parse back to what was read."""
        value: dict[str, object] = {
            "text": 'quote " backslash \\ unicode \u2013 emoji \U0001f600 del \x7f',
            "list": [1, 2.5, True, ["nested"]],
            "table": {"a key": "v"},
        }
        rendered = tomllib.loads(f"value = {toml_value(value)}\n")
        self.assertEqual(rendered["value"], value)

    def test_inspect_normalises_the_dev_group(self) -> None:
        """'Dev' is the dev group, as PEP 735 compares names."""
        with tempfile.TemporaryDirectory() as directory:
            pyproject = Path(directory, "pyproject.toml")
            text = '[project]\nname = "x"\ndependencies = ["iniconfig"]\n'
            text += '[dependency-groups]\nDev = ["pluggy"]\n'
            _ = pyproject.write_text(text, encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                _ = inspect(str(pyproject), str(Path(directory, "deps")))
            report = dict(line.split("=", 1) for line in output.getvalue().splitlines())
            self.assertEqual(report["dev_group"], "true")
            self.assertEqual(report["static_dependencies"], "true")
            dependencies = Path(directory, "deps").read_text(encoding="utf-8")
            self.assertEqual(dependencies, "iniconfig\0")
            self.assertEqual(report["project"], "true")


if __name__ == "__main__":
    _ = unittest.main()
