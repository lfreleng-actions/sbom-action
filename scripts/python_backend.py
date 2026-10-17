# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Prepare and finish the python backend's SBOM.

The action runs this with cyclonedx-bom's interpreter, as
'python -E -s -m scripts.python_backend' from its own directory, which
leaves PYTHON* variables and the user site out. Three subcommands:

  inspect <pyproject.toml> <dependencies-out>
      Before installing. Reports project (true when a PEP 621 [project]
      table names the project), reason (why not), static_dependencies
      and dev_group (a PEP 735 'dev' group exists). With static
      dependencies, writes them to <dependencies-out>, NUL-terminated,
      for the action to pass to pip as arguments: a requirements file
      would have pip expand ${VARIABLE} references, and a line break
      inside an entry would become a second requirement or an option.

  anchor <pyproject.toml> <anchor-out> <site-packages> <markers.json>
      After installing. Writes the root component's copy of the
      [project] table (see python_pyproject) and reports anchor
      (project or none), reason (why there is no anchor, or why it has
      no edges) and compatible (false when the scanned interpreter
      falls outside [project].requires-python, which a pip install of
      the dependencies alone never checks). <markers.json> is the
      scanned interpreter's marker environment, as
      marker_environment.py reports it.

  finish <scanned.json> <site-packages> <markers.json> <spec-version>
         <pyproject.toml|-> <json-out> [<xml-out>]
      After scanning. Gives every component, the project included, the
      edges whose requirement applies (see python_graph), recomputes
      the required-extra properties to match where the specification
      has properties (1.3 on), checks the result against the CycloneDX
      schema, and writes the JSON document and, given <xml-out>, the
      XML one. <pyproject.toml> is the project's own file, '-' where
      the SBOM has no root.

inspect and anchor write key=value lines to stdout.
"""

from __future__ import annotations

import sys

from scripts.python_graph import Documents, finish
from scripts.python_pyproject import anchor, inspect


def main(argv: list[str]) -> int:
    """Dispatch to a subcommand."""
    if len(argv) == 4 and argv[1] == "inspect":
        return inspect(argv[2], argv[3])
    if len(argv) == 6 and argv[1] == "anchor":
        return anchor(argv[2], argv[3], argv[4], argv[5])
    if len(argv) in (8, 9) and argv[1] == "finish":
        return finish(
            Documents(
                scanned=argv[2],
                site_packages=argv[3],
                markers=argv[4],
                spec_version=argv[5],
                pyproject=argv[6],
                json_out=argv[7],
                xml_out=argv[8] if len(argv) == 9 else None,
            )
        )
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
