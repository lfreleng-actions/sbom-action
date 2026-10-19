# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

from cyclonedx.model.bom import Bom
from cyclonedx.schema import OutputFormat, SchemaVersion

class BaseOutput:
    def output_as_string(self, *, indent: int | str | None = None) -> str: ...

def make_outputter(
    bom: Bom, output_format: OutputFormat, schema_version: SchemaVersion
) -> BaseOutput: ...
