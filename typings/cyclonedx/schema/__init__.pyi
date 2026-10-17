# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

from enum import Enum

class OutputFormat(Enum):
    JSON = 1
    XML = 2

# Releases add members as CycloneDX publishes versions; 6.4.4 stops at
# 1.5 and 11.12.0 at 1.7. The action picks one with from_version.
class SchemaVersion(Enum):
    V1_7 = (1, 7)
    V1_6 = (1, 6)
    V1_5 = (1, 5)
    V1_4 = (1, 4)
    V1_3 = (1, 3)
    V1_2 = (1, 2)
    V1_1 = (1, 1)
    V1_0 = (1, 0)
    @staticmethod
    def from_version(version: str) -> SchemaVersion: ...
