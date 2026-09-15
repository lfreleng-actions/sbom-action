<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 📋 SBOM Generator Action

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/sbom-action) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![pre-commit.ci status badge]][pre-commit.ci results page] [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lfreleng-actions/sbom-action/badge)](https://scorecard.dev/viewer/?uri=github.com/lfreleng-actions/sbom-action)
<!-- prettier-ignore-end -->

Generates CycloneDX Software Bill of Materials (SBOM) reports for
projects in any language/ecosystem.

## sbom-action

This action provides a common interface over pluggable SBOM generation
backends. The default backend wraps
[syft](https://github.com/anchore/syft), which performs static analysis
of lockfiles and filesystem content, covering Go modules, Node.js/npm,
Rust, containers, binaries and further ecosystems with a
single tool. Syft shares a vendor with
[Grype](https://github.com/anchore/grype), which the reusable workflows
in this organisation use to audit the generated SBOM in a separate,
downstream job.

A second backend drives `cyclonedx-maven-plugin` for Java projects,
where static analysis falls short. See
[Backends](#backends) for how to choose between them.

The interface mirrors
[python-sbom-action](https://github.com/lfreleng-actions/python-sbom-action),
giving callers one contract across the actions estate. Future backends
(such as `cyclonedx-npm` or `cyclonedx-gomod`) can slot in behind the
same interface through the `backend` input, without changes to calling
workflows.

## Backends

<!-- markdownlint-disable MD013 -->

| Backend          | Tool                     | Needs a toolchain | Use for                                 |
| ---------------- | ------------------------ | ----------------- | --------------------------------------- |
| `syft` (default) | syft static analysis     | No                | Go, Node.js, Rust, containers, binaries |
| `maven`          | `cyclonedx-maven-plugin` | JDK + Maven       | Java/Maven projects                     |

<!-- markdownlint-enable MD013 -->

### Why Java needs its own backend

The syft backend reads files. For most ecosystems the file it reads is
already a resolved dependency graph — `go.mod` records indirect
requirements, and `package-lock.json` and `uv.lock` are complete
resolved graphs by construction. Static analysis suits those cases.

Maven breaks that assumption. `pom.xml` is an **input to** dependency
resolution rather than a product of it, so two categories of
dependency stay invisible to
any tool that parses it as text:

- **Transitive dependencies.** A single `spring-boot-starter-web` entry
  stays one component instead of expanding to the artifacts Maven
  actually puts on the classpath. Most vulnerabilities live in
  transitive dependencies.
- **BOM-managed versions.** Where a version comes from
  `dependencyManagement` or an imported BOM, it does not exist until
  Maven resolves it, and syft emits the component with version
  `UNKNOWN`. A vulnerability database cannot match a component without
  a version, so it escapes scanning rather than merely losing
  precision. Centrally managed versions are the norm in enterprise
  Java.

The `maven` backend invokes the plugin's `makeAggregateBom` goal
directly, so the consumer's `pom.xml` needs no plugin entry and the
action modifies nothing in the checkout. `makeAggregateBom` runs once
at the reactor root and covers every module, which multi-module
projects require. The output is CycloneDX, so nothing downstream of
the SBOM
changes.

The goal resolves dependencies but does not compile, so it succeeds
against a source tree with no prior build. It fails when
dependency *resolution* fails, which is the correct signal — an
unresolvable graph means there is nothing meaningful to scan.

The plugin also emits the CycloneDX `dependencies` graph, which syft
does not. That records which direct dependency pulled in a given
transitive component, the question people actually ask when triaging a
finding.

### Trust Boundary

> ⚠️ **The `maven` backend requires a trusted checkout.** Running Maven
> against a project treats that project as *executable input* rather
> than as inert metadata.

Before the SBOM goal runs, Maven will:

- load `.mvn/extensions.xml` from the project as JVM core extensions;
- load build extensions declared in the POM;
- read command-line arguments from `.mvn/maven.config`.

No command-line flag turns any of that off, and it happens even though
the goal never compiles source or runs tests. A project supplying a
core extension thus executes code in the job.

This is a real difference from the `syft` backend, which reads files
and executes nothing from the project.

The practical consequence: **do not point the `maven` backend at
untrusted content**. In particular, a workflow that generates SBOMs on
`pull_request` from forks gives fork authors code execution on the
runner, with whatever that job's token and cache scope allow. Where
that matters, restrict the Maven SBOM job to trusted refs, or accept
the lower fidelity of the `syft` backend for untrusted ones.

## Usage Example

<!-- markdownlint-disable MD046 -->

```yaml
steps:
  - name: "Generate SBOM"
    id: sbom
    uses: lfreleng-actions/sbom-action@main
    with:
      path_prefix: '.'
```

For a Java project:

```yaml
steps:
  - name: "Generate SBOM"
    id: sbom
    uses: lfreleng-actions/sbom-action@main
    with:
      backend: 'maven'
      path_prefix: '.'
      java_version: '21'
```

<!-- markdownlint-enable MD046 -->

## Requirements

The action needs `jq`, `realpath` and `sort` (the latter two from GNU
coreutils, for `realpath -m` and `sort -V`) and `mktemp` on the runner.
GitHub-hosted Ubuntu runners include these tools; minimal self-hosted
or non-Linux runners must provide them. The action checks for them up
front and fails with a clear error naming any missing tool.

The `syft` backend downloads the syft binary via the pinned
`anchore/sbom-action/download-syft` helper, so runners need egress to
GitHub release assets.

The `maven` backend installs a JDK with `actions/setup-java` and uses
the Maven installation from the runner image, so runners need egress to
the JDK distribution and to the Maven repositories the project
resolves against (Maven Central by default). Callers running
`harden-runner` in `block` mode must allow-list those endpoints.

The pinned `actions/setup-java` v5 is a `node24` action, so the Maven
backend needs **Actions Runner v2.327.1 or later**. GitHub-hosted
runners meet this; a self-hosted runner below that version fails
before generation starts.

The JDK setup runs with `overwrite-settings: false`, so an existing
`~/.m2/settings.xml` survives. A caller that configures mirrors,
proxies or private repository credentials before invoking this action
keeps them; `setup-java` still writes its default file where none
exists.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name              | Required | Default          | Description                                                           |
| ----------------- | -------- | ---------------- | --------------------------------------------------------------------- |
| backend           | False    | `syft`           | SBOM generation backend: `syft` or `maven`                            |
| path_prefix       | False    | `.`              | Project directory; must resolve within the workspace                  |
| sbom_format       | False    | `both`           | SBOM output format: `json`, `xml`, or `both`                          |
| sbom_spec_version | False    | `1.5`            | CycloneDX specification version to use                                |
| filename_prefix   | False    | `sbom-cyclonedx` | Base filename for SBOM output (without extension)                     |
| output_directory  | False    | `.`              | SBOM report directory, within workspace or runner temp                |
| include_dev       | False    | `false`          | Include development dependencies (Maven: test scope) in SBOM          |
| fail_on_error     | False    | `true`           | Fail the action if SBOM generation encounters errors                  |
| syft_version      | False    | `''`             | Syft version to download (defaults to the installer's pinned version) |

<!-- markdownlint-enable MD013 -->

### Maven backend inputs

These apply when `backend` is `maven`, but the action validates
them on every run so a typo surfaces regardless of the backend in use.

<!-- markdownlint-disable MD013 -->

| Name                 | Required | Default   | Description                                                     |
| -------------------- | -------- | --------- | --------------------------------------------------------------- |
| java_version         | False    | `21`      | JDK version for the maven backend                               |
| java_distribution    | False    | `temurin` | JDK distribution for the maven backend                          |
| maven_plugin_version | False    | `2.9.3`   | `cyclonedx-maven-plugin` version; `2.8.0` or newer              |
| maven_args           | False    | `''`      | Extra arguments appended to the Maven call, split on whitespace |

<!-- markdownlint-enable MD013 -->

Use `maven_args` for project-specific resolution needs, for example a
managed settings file (`-s .mvn/settings.xml`) or repository
properties.

> ⚠️ **Treat `maven_args` as trusted input.** The value splits on
> whitespace without shell evaluation and without glob expansion, so it
> cannot reach a shell — but Maven itself accepts goal coordinates, so
> a token such as `com.example:some-plugin:1.0:goal` runs that plugin.
> Supply this input from the calling workflow, never from pull request
> content.

The action rejects `maven_args` values that override the properties it
owns (`outputFormat`, `outputName`, `outputDirectory`, `schemaVersion`,
`includeTestScope`, `cyclonedx.skip` and `cyclonedx.skipAttach`); use
the corresponding inputs instead. Caller arguments are also placed
before those properties on the command line, so the action's values
remain authoritative even for an override form the rejection does not
recognise. Without that, a redirected `outputDirectory` would write
outside the validated output directory and leave the reported paths and
component count pointing at files that were never generated.

## Verification After Generation

A zero exit code from either backend does not by itself mean a usable
document exists, so the action clears the destination paths before
generating and then checks the artefacts before reporting success:

- **The requested documents exist.** `cyclonedx-maven-plugin` honours
  `cyclonedx.skip`, which a consumer's own POM can set as a property;
  the plugin then exits 0 having written nothing.
- **The document declares the requested specification version.** The
  plugin falls back to its own default for a version it does not
  support rather than failing, so `sbom_spec_version: '9.9'` would
  otherwise report success over a document carrying a different
  version.

Clearing the destinations first is what makes the existence check
meaningful: a repository can legitimately contain a committed
`sbom-cyclonedx.json`, and an earlier step in the same job can leave
one behind. Without it, a backend that exits 0 without writing would
have the stale document validated and published as a fresh result.

The action clears the destinations again when generation fails,
including under `fail_on_error: false`. A rejected document is still a
document — the unsupported-spec-version case writes a well-formed BOM
carrying the wrong version — and a consumer uploading
`sbom-cyclonedx.*` would otherwise publish and scan a document this
action had already rejected.

Either condition routes through the same handling as an outright
backend failure, honouring `fail_on_error` and reporting
`component_count: 0` where the caller permits failures. A scan that
reports nothing without saying so is the failure mode this action
exists to avoid, so these conditions fail the step outright.

## Outputs

<!-- markdownlint-disable MD013 -->

| Name            | Description                                |
| --------------- | ------------------------------------------ |
| sbom_json_path  | Path to generated JSON SBOM file           |
| sbom_xml_path   | Path to generated XML SBOM file            |
| component_count | Number of components in the generated SBOM |
| backend         | SBOM generation backend used               |

<!-- markdownlint-enable MD013 -->

The action emits `sbom_json_path` for the `json` and `both` formats,
and `sbom_xml_path` for the `xml` and `both` formats; the output for a
format the caller did not request stays empty.

## Path Constraints

Relative values for `path_prefix` and `output_directory` resolve
against `GITHUB_WORKSPACE`, not the current working directory, so
behaviour stays deterministic when a calling workflow sets a custom
working directory. The action checks both directory inputs against
the runner filesystem before use: `path_prefix` must resolve within
`GITHUB_WORKSPACE`, and `output_directory` must resolve within
`GITHUB_WORKSPACE` or `RUNNER_TEMP`. Paths that escape these
locations fail the action, preventing scans or writes against
arbitrary runner filesystem locations.

## Development Dependency Scoping

The `include_dev` input controls whether development dependencies
appear in the SBOM. The syft backend maps this onto its JavaScript
cataloger (`SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES`), so for Node.js
projects the SBOM covers production dependencies by default. Go modules
have no development scope, so the input has no effect there. Further
per-ecosystem scoping options join the mapping as syft exposes them.

The maven backend maps `include_dev` onto the plugin's
`includeTestScope`. Maven's `test` scope is the analogue of npm
`devDependencies`: absent from the shipped artefact, and so excluded by
default. The plugin's other scope defaults (`compile`, `provided`,
`runtime` and `system`, all enabled) mean the BOM describes what the
project ships.

Leaving test scope out is deliberate rather than incidental. A BOM that
describes the artefact is what compliance regimes such as the EU Cyber
Resilience Act expect, and Java test trees are large and
disproportionately stale, so including them adds findings with little
bearing on production risk. Set `include_dev: 'true'` where
build-system supply-chain visibility matters more than describing the
shipped artefact.

Note that the plugin's `skipNotDeployed` default also excludes modules
that set `maven.deploy.skip`, which is consistent with describing the
artefact but can surprise anyone counting components on a project with
non-deployed test-harness modules.

## Monorepo and Nested Module Support

Point `path_prefix` at the directory containing the project's
lockfile/manifest. This supports repositories where the module is not
at the repository root, for example Gerrit-hosted monorepos such as
`onap/multicloud-k8s`, where Go modules live under `src/`:

<!-- markdownlint-disable MD046 -->

```yaml
steps:
  - name: "Generate SBOM for nested module"
    uses: lfreleng-actions/sbom-action@main
    with:
      path_prefix: 'src/k8splugin'
```

<!-- markdownlint-enable MD046 -->

## Workflow Integration

The reusable workflows in this organisation keep SBOM generation and
SBOM auditing in separate jobs, connected by an artifact. The
generation job runs this action and uploads the results; a downstream
job downloads them and audits with Grype. This separation keeps
failure modes independent and preserves the SBOM for inspection even
when the audit fails:

<!-- markdownlint-disable MD046 -->

```yaml
- name: "Generate SBOM"
  id: sbom
  uses: lfreleng-actions/sbom-action@main

- name: "Upload SBOM artifact"
  uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
  with:
    name: sbom-files
    path: sbom-cyclonedx.*
    if-no-files-found: error
```

<!-- markdownlint-enable MD046 -->

## Implementation Details

<!-- markdownlint-disable MD013 -->

1. **Input Validation**: Validates backend, format, boolean flags, specification version, filename prefix and the maven-backend inputs (all against restricted character sets) before use; verifies the project directory exists
2. **Toolchain Setup**: For the `syft` backend, fetches the syft binary via the pinned `anchore/sbom-action/download-syft` helper action. For the `maven` backend, installs a JDK via the pinned `actions/setup-java`. The selected backend guards each step, so neither costs anything when unused
3. **SBOM Generation**: A single step dispatches on the backend. The `syft` backend runs one scan emitting the requested CycloneDX formats (`format@version=path` syntax). The `maven` backend invokes `cyclonedx-maven-plugin`'s `makeAggregateBom` goal directly, writing into the resolved output directory. In both cases the JSON document always gets generated internally to compute the component count
4. **Outputs and Summary**: Emits output paths for the requested formats, the component count, and a step summary

<!-- markdownlint-enable MD013 -->

The plugin writes every requested format into one directory and cannot
split them, so a run requesting `xml` alone generates both formats into
a scratch directory under `RUNNER_TEMP` and moves the XML into place.
Writing the JSON into the output directory instead
would leave behind a document the caller did not request, which the
`sbom-cyclonedx.*` artifact glob would then collect.

## Notes

- The generated filenames follow the `sbom-cyclonedx.*` convention the
  organisation's reusable workflows consume (the `sbom-files` artifact
  contract)
- The `syft` backend reads lockfiles/manifests without installing
  project dependencies, so generation is fast and needs no language
  toolchain. The `maven` backend necessarily gives up that property:
  resolving a Maven dependency graph requires Maven
- For Python projects, prefer
  [python-sbom-action](https://github.com/lfreleng-actions/python-sbom-action):
  its environment-based generation gives higher-fidelity results for
  resolved Python dependency graphs
- For Java projects, use `backend: maven` rather than the default. The
  `syft` backend will produce an SBOM for a Maven project, but one that
  omits transitive dependencies and reports BOM-managed versions as
  `UNKNOWN`

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/sbom-action/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/sbom-action/main.svg
