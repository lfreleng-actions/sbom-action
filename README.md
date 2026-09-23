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

A second backend runs the CycloneDX project's own build-tool plugins
for Java projects, where static analysis falls short. See
[Backends](#backends) for how to choose between them.

The interface mirrors
[python-sbom-action](https://github.com/lfreleng-actions/python-sbom-action),
giving callers one contract across the actions estate. Future backends
(such as `cyclonedx-npm` or `cyclonedx-gomod`) can slot in behind the
same interface through the `backend` input, without changes to calling
workflows.

## Backends

A backend names the **tool that produces the document**, not the build
system it drives.

<!-- markdownlint-disable MD013 -->

| Backend          | Tool                             | Build tools driven | Needs a toolchain | Use for                                 |
| ---------------- | -------------------------------- | ------------------ | ----------------- | --------------------------------------- |
| `syft` (default) | syft static analysis             | none               | No                | Go, Node.js, Rust, containers, binaries |
| `cyclonedx`      | CycloneDX build-tool plugins     | Maven, Gradle      | JDK + build tool  | Java projects                           |

<!-- markdownlint-enable MD013 -->

`cyclonedx-gradle-plugin` is the same tool family solving the same
problem as `cyclonedx-maven-plugin`, so Gradle joins the **existing**
`cyclonedx` backend rather than arriving as a separate one. Callers keep
the same `backend` value, and the action resolves the build system from
the project unless the caller declares it.

Because the backend name does not identify the build system, the
`dependency_manager` output reports which one ran (`maven` or `gradle`).
It stays empty for `syft`, which drives no build tool.

The `cyclonedx` backend fails fast when it cannot find a build system
it supports, rather than attempting an invocation that cannot work.

### Why Java needs a different backend

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

The `cyclonedx` backend invokes the plugin's `makeAggregateBom` goal
directly, so the consumer's `pom.xml` needs no plugin entry and the
build leaves no `target/` directories behind. `makeAggregateBom` runs
once at the reactor root and covers every module, which multi-module
projects require. The output is CycloneDX, so nothing downstream of
the SBOM changes.

The action does write its report files, which land in the checkout
whenever `output_directory` points there — as the default `.` does.
What it leaves alone is the project itself: it edits no POM or build
script, and produces no build output.

The goal resolves dependencies but does not compile, so it succeeds
against a source tree with no prior build. It fails when
dependency *resolution* fails, which is the correct signal — an
unresolvable graph means there is nothing meaningful to scan.

The plugin also emits the CycloneDX `dependencies` graph, which syft
does not. That records which direct dependency pulled in a given
transitive component, the question people actually ask when triaging a
finding.

### Trust Boundary

> ⚠️ **The `cyclonedx` backend requires a trusted checkout.** Running Maven
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

The practical consequence: **do not point the `cyclonedx` backend at
untrusted content**. The action defends this by default — see
[Untrusted checkouts](#untrusted-checkouts).

### Untrusted checkouts

Nothing turns that execution off, so the remaining control is whether
to run the backend at all. The `untrusted_checkout` input decides:

<!-- markdownlint-disable MD013 -->

| Value            | Meaning                                                                     |
| ---------------- | --------------------------------------------------------------------------- |
| `auto` (default) | Treat a pull request whose head is outside the base repository as untrusted |
| `true`           | Caller declares the checkout untrusted                                      |
| `false`          | Caller declares the checkout trusted                                        |

<!-- markdownlint-enable MD013 -->

When the checkout resolves to untrusted, the `cyclonedx` backend is
**skipped**. The step succeeds, `skipped` reports `true`, and the
action writes no document — clearing both destination paths first, so
a committed or leftover document cannot survive the skip for a
caller's artifact glob to collect. This does not affect the `syft`
backend, which executes nothing from the project.

> One qualification: a guard protects the clearing. Where a
> destination holds something the action cannot identify as a
> CycloneDX document, it refuses rather than removing, and the step
> fails instead of skipping. For an existing **XML** destination that
> classification needs `xmllint`, which GitHub-hosted runners lack —
> see [Requirements](#requirements). A fresh checkout has no such
> file, so this does not arise in ordinary use.

Clearing covers both paths the action owns for its `filename_prefix`,
rather than the format a given run emits. A run emitting JSON alone
still clears the sibling XML, because the documented artifact glob
(`sbom-cyclonedx.*`) would otherwise publish a stale XML from an
earlier run as though this run had produced it. A caller accumulating
formats across separate runs must give each run its own
`filename_prefix` or `output_directory`.

Three deliberate choices there:

- **Skip rather than fail.** An untrusted contribution should not turn
  into a red build over something the contributor cannot fix. Callers
  that want a hard gate can branch on the `skipped` output.
- **Skip rather than fall back to `syft`.** A fallback would emit a
  document missing the transitive graph and carrying `UNKNOWN`
  versions, which reads downstream as a clean scan. No SBOM is honest;
  a misleading one is worse than nothing.
- **Report nothing rather than zero.** `component_count` and the path
  outputs stay **empty**, not `0`, so nothing can read a skip as a
  scan that found nothing.

#### `auto` cannot see everything

`auto` classifies as untrusted a pull request whose head lives outside
the base repository, a pull request with no readable head repository,
and every `merge_group` event — a merge queue may hold
fork-originated changes and carries no head repository to check them
against.

The test is **cross-repository, not unmerged**. Someone with write
access pushed that same-repository branch, and the same access lets
them push to the default branch; classifying their pull request as
untrusted would disable this backend for pull request scanning without
raising a bar they do not already clear. Callers whose threat model
includes write-access contributors should set `untrusted_checkout:
'true'` and scan on the default branch instead.

It will **not** catch, among others:

- a Gerrit refspec checkout, which carries unreviewed contributor code
  with no pull request context at all;
- a `workflow_run` triggered by an untrusted workflow;
- any checkout the caller performed from an arbitrary ref.

Callers that know the context must say so with `untrusted_checkout:
'true'`. Where a workflow already gathers repository context,
[repository-metadata-action](https://github.com/lfreleng-actions/repository-metadata-action)
exposes an `is_fork` output to wire straight in.

> Note that `is_fork` there derives from `head.repo.fork` — whether the
> head repository is itself a fork — a slightly broader test than the
> cross-repository comparison `auto` performs.

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
      backend: 'cyclonedx'
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

`xmllint` (from `libxml2-utils`) covers one narrow case: an XML file
already sitting at the output destination. The action uses it to tell
a CycloneDX document from an unrelated XML file before replacing one,
and refuses the collision with a message naming the tool when the
runner lacks it.

> **GitHub-hosted runners do not ship `xmllint`.** That does not affect
> ordinary use — each job checks out afresh, so the destination is
> empty and no classification happens. It comes up where something
> already occupies the XML destination, such as a committed
> `sbom-cyclonedx.xml` or a second run in the same job writing to the
> same prefix. Install `libxml2-utils`, or give each run its own
> `filename_prefix` or `output_directory`.

The `syft` backend downloads the syft binary via the pinned
`anchore/sbom-action/download-syft` helper, so runners need egress to
GitHub release assets.

The `cyclonedx` backend installs a JDK with `actions/setup-java`, so
runners need egress to the JDK distribution and to the repositories the
project resolves against (Maven Central by default). Gradle adds the
Gradle distribution host, which the wrapper downloads from, and the
Gradle Plugin Portal, where `cyclonedx-gradle-plugin` resolves from
rather than Maven Central. Callers running `harden-runner` in `block`
mode must allow-list those endpoints.

For Maven the action uses the installation from the runner image. For
Gradle it runs the project's `gradlew` where the checkout has one, and
otherwise a `gradle` on `PATH` — so a project without a committed
wrapper needs Gradle installed on the runner.

That backend also needs **Maven 3.6.1 or later**. The plugin itself
supports older Maven, but the action passes `--no-transfer-progress`
to keep download chatter out of the log, and that flag arrived in
3.6.1. GitHub-hosted runners ship a far newer Maven; a self-hosted
runner pinned below 3.6.1 fails on the flag.

The pinned `actions/setup-java` v5 is a `node24` action, so the
`cyclonedx` backend needs **Actions Runner v2.327.1 or later**.
GitHub-hosted runners meet this; a self-hosted runner below that
version fails before generation starts.

The JDK setup runs with `overwrite-settings: false`, so an existing
`~/.m2/settings.xml` survives. A caller that configures mirrors,
proxies or private repository credentials before invoking this action
keeps them; `setup-java` still writes its default file where none
exists.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name              | Required | Default          | Description                                                           |
| ----------------- | -------- | ---------------- | --------------------------------------------------------------------- |
| backend           | False    | `syft`           | SBOM generation backend: `syft` or `cyclonedx`                        |
| path_prefix       | False    | `.`              | Project directory; must resolve within the workspace                  |
| sbom_format       | False    | `both`           | SBOM output format: `json`, `xml`, or `both`                          |
| sbom_spec_version | False    | `1.5`            | CycloneDX specification version to use                                |
| filename_prefix   | False    | `sbom-cyclonedx` | Base filename for SBOM output (without extension)                     |
| output_directory  | False    | `.`              | SBOM report directory, within workspace or runner temp                |
| include_dev       | False    | `false`          | Include development dependencies (Maven: test scope) in SBOM          |
| fail_on_error     | False    | `true`           | Fail the action if SBOM generation encounters errors                  |
| syft_version      | False    | `''`             | Syft version to download (defaults to the installer's pinned version) |

<!-- markdownlint-enable MD013 -->

### CycloneDX backend inputs

These apply when `backend` is `cyclonedx`, but the action validates
them on every run so a typo surfaces regardless of the backend in use.

<!-- markdownlint-disable MD013 -->

| Name                  | Required | Default   | Description                                                      |
| --------------------- | -------- | --------- | ---------------------------------------------------------------- |
| dependency_manager    | False    | `auto`    | Build tool: `auto`, `maven` or `gradle`                          |
| java_version          | False    | `21`      | JDK version for the cyclonedx backend                            |
| java_distribution     | False    | `temurin` | JDK distribution for the cyclonedx backend                       |
| maven_plugin_version  | False    | `2.9.3`   | `cyclonedx-maven-plugin` version; `2.8.0` or newer               |
| maven_args            | False    | `''`      | Extra arguments appended to the Maven call, split on whitespace  |
| gradle_plugin_version | False    | `3.4.1`   | `cyclonedx-gradle-plugin` version; `3.0.0` or newer              |
| gradle_version        | False    | `''`      | Gradle version the project uses; empty asks the build tool       |
| gradle_args           | False    | `''`      | Extra arguments appended to the Gradle call, split on whitespace |
| untrusted_checkout    | False    | `auto`    | Is the checkout untrusted: `auto`, `true` or `false`             |

<!-- markdownlint-enable MD013 -->

#### Choosing the build tool

Left at `auto`, the action reads the project directory: a `pom.xml`
selects Maven, a Gradle build script selects Gradle, and a tree carrying
both resolves as Maven.

That last case is a guess about intent, and a caller often knows better.
A reusable workflow dedicated to one build tool always does, because the
caller chose that workflow. `build-metadata-action` reports the same
fact as `build_tool`, so a lane can pass it straight through:

```yaml
- uses: lfreleng-actions/sbom-action@<sha>
  with:
    backend: cyclonedx
    dependency_manager: gradle
```

A declared value still has to describe the checkout. Naming `maven` for
a tree with no `pom.xml` fails with that explanation, rather than
surfacing a confusing error from inside a build tool the project does
not use.

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

#### Gradle specifics

The action runs `cyclonedxBom` on the root project, which combines the
per-project documents from **every** project in the build, including
nested ones. A grandchild such as `:app:nested` contributes its own
dependencies to the result, not merely its project component — measured
against a fixture whose nested module carries a coordinate nothing else
in the build uses:

```text
cyclonedxBom
cyclonedxDirectBom
app:cyclonedxDirectBom
app:nested:cyclonedxDirectBom
core:cyclonedxDirectBom
```

That topology is worth stating because tooling which walks a Gradle
build often stops at the root's immediate subprojects, and a flat
reactor cannot tell the two behaviours apart.

`gradle_args` carries the same warning and the same protections as
`maven_args`: it splits on whitespace without shell evaluation, but
Gradle accepts arguments that change which build runs. The action
rejects `-p`, `-c`, `-b` and `-I` in every spelling, because each
selects a different project, settings file, build file or init script —
any of which would resolve a build outside the validated directory and
describe it in an SBOM labelled with `path_prefix`. It also rejects any
`-D` naming an `sbomAction.*` property, which is how the action passes
its own configuration.

An init script applies the plugin, so the consumer's build files need no
entry. Unlike the Maven branch, which invokes a goal directly, Gradle
configures the build and so creates `.gradle/` and `build/` directories
in the checkout. That is inherent to running Gradle at all. What the
action does prevent is the plugin leaving its own reports there: it
redirects both the combined document and the per-project intermediates,
keeping an artifact glob from collecting a report the caller never
asked for.

`gradle_version` exists for the floor check described below. Supplying
it — from `build-metadata-action`'s `java_gradle_version`, for example —
settles the question before the action downloads anything. Left empty,
the action asks the build tool, which is authoritative but pays for the
distribution first.

#### Gradle versions below the plugin floor

`cyclonedx-gradle-plugin` 3.x requires **Gradle 8.4 or newer**. Below
that the task names differ and the requested CycloneDX schema may not
exist, so the run cannot yield a document worth scanning.

The effective floor is the later of that and Gradle's own Java
compatibility, because Gradle also has to run on the JDK this action
installs. On the default `java_version: 21` Gradle reaches support at
**8.5**, so that is the floor a default configuration applies:

| `java_version` | Gradle floor   |
| -------------- | -------------- |
| 17 to 20       | 8.4            |
| 21             | 8.5            |
| 22             | 8.8            |
| 23             | 8.10           |
| 24             | 8.14           |
| 25             | 9.1            |

A `java_version` outside that range leaves the plugin's 8.4 standing
alone: inventing a floor for a release whose compatibility nobody has
recorded would be a guess, and Gradle reports an unsupported JVM well
enough on its own.

The action **skips** rather than fails. An SBOM audit is not essential
to a build, other auditing tools exist, and failing a pipeline over a
plugin's declared dependency would punish a project for something
unrelated to its own code. The run reports why, `skipped` returns
`true`, and the action writes no document and reports no count — leaving
the project free to raise its wrapper version and get results.

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
exists to avoid, so these conditions count as generation failures
rather than quiet successes.

## Outputs

<!-- markdownlint-disable MD013 -->

| Name               | Description                                        |
| ------------------ | -------------------------------------------------- |
| sbom_json_path     | Path to generated JSON SBOM file                   |
| sbom_xml_path      | Path to generated XML SBOM file                    |
| component_count    | Number of components in the generated SBOM         |
| backend            | SBOM generation backend used                       |
| dependency_manager | Build tool the `cyclonedx` backend drove           |
| skipped            | `true` when the action declined to generate        |

<!-- markdownlint-enable MD013 -->

The action emits `sbom_json_path` for the `json` and `both` formats,
and `sbom_xml_path` for the `xml` and `both` formats; the output for a
format the caller did not request stays empty.

`dependency_manager` reports the build system the `cyclonedx` backend
drove, since the backend name identifies the tool rather than the build
system. It stays empty for `syft`.

`skipped` reports `true` when the action declined to generate. Two
conditions cause that:

<!-- markdownlint-disable MD013 -->

| Condition                        | `dependency_manager` | Documented at                                                                     |
| -------------------------------- | -------------------- | --------------------------------------------------------------------------------- |
| Untrusted checkout               | **empty**            | [Untrusted checkouts](#untrusted-checkouts)                                       |
| Gradle below the effective floor | `gradle`             | [Gradle versions below the plugin floor](#gradle-versions-below-the-plugin-floor) |

<!-- markdownlint-enable MD013 -->

In both cases `sbom_json_path`, `sbom_xml_path` and `component_count`
are **empty**, and `backend` still reports the backend the caller
selected, since validation resolves it before either decision.

`dependency_manager` differs between them because validation resolves
the build system after the trust decision but before it can weigh the
Gradle floor. A caller branching on a skip should read `skipped` rather
than inferring it from empty build-tool metadata.

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

The cyclonedx backend maps `include_dev` onto the plugin's
`includeTestScope`. Maven's `test` scope is the analogue of npm
`devDependencies`: absent from the running application, and so
excluded by default.

The plugin's other scope defaults stay as they are — `compile`,
`runtime`, **`provided`** and **`system`** all enabled — so the BOM
describes **what the application depends on at runtime**, a wider set
than what the build packages into the artefact. That distinction
matters for `provided` and `system`: a servlet API or JDBC driver
supplied by the container is absent from the JAR yet present when the
application runs, and a vulnerability in one carries real risk.
Excluding them would hide part of the deployed attack surface.

> If your use for the SBOM is strictly "what this build packages",
> rather than "what this application runs against", pass
> `-DincludeProvidedScope=false -DincludeSystemScope=false` through
> `maven_args`. The action does not reserve those two properties.

Leaving test scope out is deliberate rather than incidental. Test
dependencies are absent from every deployment, so a finding in one
carries no production risk, and Java test trees are large and
disproportionately stale. Compliance regimes such as the EU Cyber
Resilience Act expect a BOM describing the product rather than its
build harness. Set `include_dev: 'true'` where build-system
supply-chain visibility matters more.

Note that the plugin's `skipNotDeployed` default also excludes modules
that set `maven.deploy.skip`, which is consistent with describing the
deployed product but can surprise anyone counting components on a
project with non-deployed test-harness modules.

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

1. **Input Validation**: Validates backend, format, boolean flags, specification version, filename prefix, and the `java_version`, `java_distribution`, `maven_plugin_version`, `gradle_plugin_version`, `gradle_version`, `dependency_manager` and `untrusted_checkout` inputs against restricted value sets before use; verifies the project directory exists. `maven_args` and `gradle_args` are **not** constrained this way — the action splits each on whitespace and rejects them solely for selecting an alternate project or overriding action-owned properties, leaving them trusted input (see [Inputs](#inputs)). For the `cyclonedx` backend this step also resolves the trust decision and the build system, failing fast on one it cannot drive before installing any toolchain, and skips a Gradle version below the plugin's floor where the caller supplied one
2. **Toolchain Setup**: For the `syft` backend, fetches the syft binary via the pinned `anchore/sbom-action/download-syft` helper action. For the `cyclonedx` backend, installs a JDK via the pinned `actions/setup-java`. The selected backend guards each step, so neither costs anything when unused
3. **SBOM Generation**: A single step dispatches on the backend, and the `cyclonedx` backend dispatches again on the build system. The `syft` backend runs one scan emitting the requested CycloneDX formats (`format@version=path` syntax). For Maven, the action invokes `cyclonedx-maven-plugin`'s `makeAggregateBom` goal directly, writing into the resolved output directory. For Gradle, an init script applies `cyclonedx-gradle-plugin` and runs `cyclonedxBom`, configuring the task destinations once Gradle finishes evaluating the consumer's build scripts, so that a consumer's own configuration cannot displace them. In both cases the JSON document always gets generated internally to compute the component count
4. **Outputs and Summary**: Emits output paths for the requested formats, the component count, the build tool used, and a step summary

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
  toolchain. The `cyclonedx` backend necessarily gives up that property:
  resolving a Maven dependency graph requires Maven
- For Python projects, prefer
  [python-sbom-action](https://github.com/lfreleng-actions/python-sbom-action):
  its environment-based generation gives higher-fidelity results for
  resolved Python dependency graphs
- For Java projects, use `backend: cyclonedx` rather than the default. The
  `syft` backend will produce an SBOM for a Maven project, but one that
  omits transitive dependencies and reports BOM-managed versions as
  `UNKNOWN`

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/sbom-action/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/sbom-action/main.svg
