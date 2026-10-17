# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Type stubs for the small part of cyclonedx-python-lib that
# scripts/python_graph.py uses. The library is about 8 MiB, but adding
# it to the basedpyright hook took that environment, which carries a
# Node.js runtime, past pre-commit.ci's 250 MiB limit. The signatures
# match cyclonedx-python-lib 6.4.4 (with cyclonedx-bom 4.0.0) through
# 11.12.0 (with 7.5.0); the CI jobs exercise the real library.
