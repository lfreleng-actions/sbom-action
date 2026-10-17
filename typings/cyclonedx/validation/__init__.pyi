# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

from cyclonedx.schema import OutputFormat, SchemaVersion

class BaseSchemabasedValidator:
    # None when the document is valid; otherwise the error, or in newer
    # releases an iterable of them
    def validate_str(self, data: str) -> object | None: ...

def make_schemabased_validator(
    output_format: OutputFormat, schema_version: SchemaVersion
) -> BaseSchemabasedValidator: ...
