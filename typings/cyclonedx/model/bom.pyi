# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

class Bom:
    # Added at runtime by py-serializable; None when nothing deserialises
    @classmethod
    def from_json(cls, data: dict[str, object]) -> Bom | None: ...
