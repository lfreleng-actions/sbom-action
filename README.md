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
projects in any language/ecosystem, and for container images.

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
for Java and Rust projects, where static analysis falls short, and a
third generates Python SBOMs from an installed environment. See
[Backends](#backends) for how to choose between them.

The `mode` input chooses what the document describes: a project
directory (the default), or one SBOM per container image from docker
archives. See [Container images](#container-images).

The interface began as a mirror of
[python-sbom-action](https://github.com/lfreleng-actions/python-sbom-action),
which the `python` backend now replaces, giving callers one contract
across the actions estate. See
[Migrating from python-sbom-action](#migrating-from-python-sbom-action).
Future backends (such as `cyclonedx-npm` or `cyclonedx-gomod`) can slot
in behind the same interface through the `backend` input, without
changes to calling workflows.

## Backends

A backend names the **tool that produces the document**, not the build
system it drives.

<!-- markdownlint-disable MD013 -->

| Backend          | Tool                         | Build tools driven                      | Needs a toolchain                   | Use for                                 |
| ---------------- | ---------------------------- | --------------------------------------- | ----------------------------------- | --------------------------------------- |
| `syft` (default) | syft static analysis         | none                                    | No                                  | Go, Node.js, Rust, containers, binaries |
| `cyclonedx`      | CycloneDX build-tool plugins | Maven, Gradle, Cargo                    | JDK + build tool, or Rust toolchain | Java and Rust projects                  |
| `python`         | `cyclonedx-py` (CycloneDX)   | uv, PDM, Poetry, Pipenv, pip-tools, pip | Python (installed by the action)    | Python projects                         |

<!-- markdownlint-enable MD013 -->

`cyclonedx-gradle-plugin` is the same tool family solving the same
problem as `cyclonedx-maven-plugin`, so Gradle joins the **existing**
`cyclonedx` backend rather than arriving as a separate one, and so does
`cargo-cyclonedx` for Rust. Callers keep the same `backend` value, and
the action resolves the build system from the project unless the caller
declares it.

Because the backend name does not identify the build system, the
`dependency_manager` output reports which one ran (`maven`, `gradle` or
`cargo`, or for `python` the package manager: `uv`, `pdm`, `poetry`,
`pipenv`, `pip-tools` or `pip`).
It stays empty for `syft`, which drives no build tool.

The `cyclonedx` and `python` backends fail fast when they cannot find a
project they support, rather than attempting an invocation that cannot
work.

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

### Why Rust can use it too

`Cargo.lock` is a resolved graph, so syft does find every crate in a
Rust project, and more besides: the lockfile lists every crate that
any target, test or build script could need, and syft records no scope
and no edges for them. Under syft,
`include_dev: false` means nothing for Rust.

`cargo-cyclonedx` works from `cargo metadata`, cargo's own resolution.
It leaves dev-dependencies out, marks build-dependencies, honours the
target platform and emits the `dependencies` graph a scanner needs to
tell a crate the project declares from one it inherits. See
[Cargo specifics](#cargo-specifics).

### Why Python has its own backend

Python is the one backend named after an ecosystem rather than a tool,
because its tool works differently. `cyclonedx-py` reads the
distribution metadata of an **installed** environment rather than a
lock file, so the action has to build that environment first, with the
package manager the project uses, and the backend owns that sequence:
check the lock, install, then scan. An environment is the most
faithful description Python offers: it holds what the resolver chose
for this interpreter and platform, with environment markers already
applied, and each distribution's own record of what it requires, which
is where the `dependencies` graph comes from.

A separate backend also keeps Python's detection apart. A Python
project often carries a `Cargo.toml` for a native extension (PyO3,
maturin) that the `cyclonedx` backend's detection would claim.

The backend absorbs
[python-sbom-action](https://github.com/lfreleng-actions/python-sbom-action),
keeping its detection order and `dependency_manager` values, and fixes
four defects along the way:

- **Tooling in the SBOM.** python-sbom-action installed `cyclonedx-bom`
  into the environment it scanned, so its own dependency tree appeared
  in every document as though the project used it. The project's
  dependencies now install into an environment of their own, which
  holds nothing else — not even `pip`.
- **No root component.** A root appeared solely for a project with no
  lock file at all; every lock-file project produced edges with nothing
  to anchor them, so nothing could tell a direct dependency from an
  inherited one. Any project with a PEP 621 `[project]` table now gets
  one. See [Python specifics](#python-specifics).
- **Scanning the runner.** A project carrying a `pyproject.toml` and no
  lock or requirements file installed nothing, and the scan described
  the runner's own Python instead. Its declared dependencies now install
  like any other.
- **An unpinned installer script.** uv came from
  `curl https://astral.sh/uv/install.sh | sh`; every package manager
  now comes from PyPI into a separate environment.

### Trust Boundary

> ⚠️ **The `cyclonedx` backend requires a trusted checkout.** Running a
> build tool against a project treats that project as *executable input*
> rather than as inert metadata.

Before the SBOM goal runs, Maven will:

- load `.mvn/extensions.xml` from the project as JVM core extensions;
- load build extensions declared in the POM;
- read command-line arguments from `.mvn/maven.config`.

Gradle goes further, because evaluating a build *is* running code:

- `settings.gradle`/`settings.gradle.kts` and every `build.gradle`
  script execute as Groovy or Kotlin during configuration;
- `gradle.properties` can set JVM arguments for the build process;
- where the checkout carries a wrapper, `gradlew` is a shell script from
  the project and `gradle-wrapper.jar` is a binary it executes, which
  the action runs in preference to any `gradle` on `PATH`.

Cargo resolves without compiling, but still reads configuration that
names programs to run:

- `.cargo/config.toml` can set `build.rustc-wrapper`, which
  `cargo metadata` and `cargo-cyclonedx` both execute (measured);
- `rust-toolchain.toml` selects the toolchain, which can be a
  directory inside the checkout, and the action runs cargo from the
  project directory so that file applies.

The `python` backend installs the project's dependencies, and Python
installation runs code:

- a dependency published without a wheel builds from source, running
  its build backend — `setup.py` among them — and a requirements file
  can name a local directory, which builds from the checkout;
- a project whose dependencies are dynamic needs its build backend to
  compute them, so the action builds it;
- the environment's interpreter runs the `.pth` files installed
  packages carry whenever it starts, which it does for the scan.

No command-line flag turns any of that off, and for Maven it happens
even though the goal never compiles source or runs tests. A project
supplying a core extension, a build script, a wrapper, a cargo
configuration or a package built from source thus executes code in the
job.

This is a real difference from the `syft` backend, which reads files
and executes nothing from the project.

The practical consequence: **do not point the `cyclonedx` or `python`
backend at untrusted content**. The action defends this by default —
see [Untrusted checkouts](#untrusted-checkouts).

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

When the checkout resolves to untrusted, the `cyclonedx` and `python`
backends are **skipped**. The step succeeds, `skipped` reports `true`,
and the action writes no document — clearing both destination paths
first, so a committed or leftover document cannot survive the skip for
a caller's artifact glob to collect. This does not affect the `syft`
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
untrusted would disable these backends for pull request scanning
without raising a bar they do not already clear. Callers whose threat
model includes write-access contributors should set
`untrusted_checkout: 'true'` and scan on the default branch instead.

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

The skip protects the SBOM job's own context: its token, permissions,
secrets and runner. An earlier job that ran the same checkout's code
does not, by itself, make that safe, since each job has its own. A
reusable workflow can pass `untrusted_checkout: 'false'` so fork pull
requests keep their SBOM when the SBOM job holds **nothing** the
earlier job did not: no wider `permissions`, no secrets that job
lacked, and the same class of runner. The Java workflows pass it on
that basis. Where the SBOM job holds more, keep `auto`.

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

For a Rust project built with features, describing the build those
features produce:

```yaml
steps:
  - name: "Generate SBOM"
    id: sbom
    uses: lfreleng-actions/sbom-action@main
    with:
      backend: 'cyclonedx'
      dependency_manager: 'cargo'
      path_prefix: '.'
      cargo_features: 'serde, my-crate/tls'
      cargo_no_default_features: 'true'
```

For a Python project:

```yaml
steps:
  - name: "Generate SBOM"
    id: sbom
    uses: lfreleng-actions/sbom-action@main
    with:
      backend: 'python'
      path_prefix: '.'
```

<!-- markdownlint-enable MD046 -->

## Requirements

The action needs `jq`, `realpath` and `sort` (the latter two from GNU
coreutils, for `realpath -m` and `sort -V`) and `mktemp` on the runner,
plus `tar` in image mode.
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

For Maven and Gradle the `cyclonedx` backend installs a JDK with
`actions/setup-java`, so runners need egress to the JDK distribution and
to the repositories the
project resolves against (Maven Central by default). Gradle adds the
Gradle distribution host, which the wrapper downloads from, and the
Gradle Plugin Portal, where `cyclonedx-gradle-plugin` resolves from
rather than Maven Central. Callers running `harden-runner` in `block`
mode must allow-list those endpoints.

For Maven the action uses the installation from the runner image. For
Gradle it runs the project's `gradlew` where the checkout has one, and
otherwise a `gradle` on `PATH`.

A project without a committed wrapper needs Gradle installed on the
runner. GitHub-hosted images ship one; a self-hosted runner may not.
Where neither is present the run fails with Gradle's own "command not
found", which `fail_on_error: false` downgrades to a warning — so a
missing toolchain need not fail the job. Committing a wrapper is the
better remedy: it pins the Gradle version the project asks for rather
than whichever the runner happens to carry, and `gradle-build-action`
expects one.

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

For Cargo the backend installs no JDK. It needs a **Rust toolchain on
the runner** (`cargo` on `PATH`); GitHub-hosted images ship `rustup`,
and the run fails before installing anything where `cargo` is absent.
The action pins no toolchain: cargo runs from the project directory, or
from `cargo_working_directory` where set, and the `rust-toolchain.toml`
found from there applies, so `rustup` may install the toolchain it
names. A caller wanting a particular toolchain
sets it up before this action.

`taiki-e/install-action` fetches `cargo-cyclonedx`, and for XML
output `cyclonedx-cli`, as prebuilt release binaries checked against
the SHA-256 digests in its pinned manifest. It never falls back to
compiling them from source, so a runner platform without a prebuilt
binary fails. `cyclonedx-cli` is a self-contained .NET binary of
about 80 MB; `sbom_format: json` skips it. Runners need egress to
GitHub release assets, to the crates.io index and download hosts
(`index.crates.io`, `static.crates.io`) or the registries the project
resolves against, and to the `rustup` distribution host where the
project's toolchain is not installed yet.

The `python` backend installs Python with `actions/setup-python`
(`python_version`, default `3.12`), leaving the job's own Python and
`PATH` as they were. It then installs the package manager — the latest
release, which reads the newest lock formats — and `cyclonedx-bom` from
PyPI, so runners need egress to `pypi.org` and
`files.pythonhosted.org`, or the index `PIP_INDEX_URL` names. The
project's dependencies resolve against the indexes the project or
caller configures. The action never downloads a Python of its own; see
below. The organisation's shared harden-runner allow-list carries each
of these.

`python_version` decides the interpreter for every package manager, uv
included, so it has to meet the project's `requires-python`. uv runs
bound to that interpreter (`UV_PYTHON`) with Python downloads disabled,
and neither `requires-python` nor a `.python-version` can make it fetch
another. Left unbound, uv picks the newest Python a project allows and
downloads it, a release new enough to lack wheels, so the install
compiles dependencies from source until the job times out
([python-sbom-action#151](https://github.com/lfreleng-actions/python-sbom-action/issues/151)).
A `python_version` the project rejects fails the run at the lock check,
within seconds, with an error naming the input. It must be **3.10 or
later**: every older
release is end of life, and the current releases of pip, uv, PDM,
Poetry and Pipenv all require 3.10. Validation refuses anything older.
The action's own tests run on every release from 3.10 to 3.15. On 3.10,
which lacks `tomllib`, the action installs `tomli` for its own
`pyproject.toml` reader.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name                    | Required | Default          | Description                                                                              |
| ----------------------- | -------- | ---------------- | ---------------------------------------------------------------------------------------- |
| backend                 | False    | `syft`           | SBOM generation backend: `syft`, `cyclonedx` or `python`                                 |
| mode                    | False    | `directory`      | What to describe: `directory` (`path_prefix`) or `image`                                 |
| path_prefix             | False    | `.`              | Project directory; must resolve within the workspace                                     |
| image_archive_directory | False    | `''`             | Image mode: directory of docker archives, one image per `*.tar` file                     |
| sbom_format             | False    | `both`           | SBOM output format: `json`, `xml`, or `both`                                             |
| sbom_spec_version       | False    | `1.5`            | CycloneDX specification version to use                                                   |
| filename_prefix         | False    | `sbom-cyclonedx` | Base filename for SBOM output (without extension)                                        |
| output_directory        | False    | `.`              | SBOM report directory, within workspace or runner temp                                   |
| include_dev             | False    | `false`          | Include development dependencies in SBOM; see [scoping](#development-dependency-scoping) |
| fail_on_error           | False    | `true`           | Fail the action if SBOM generation encounters errors                                     |
| syft_version            | False    | `''`             | Syft version to download (defaults to the installer's pinned version)                    |

<!-- markdownlint-enable MD013 -->

### CycloneDX and Python backend inputs

These apply when `backend` is `cyclonedx` or `python` (the first two
to both), but the action validates them on every run so a typo
surfaces regardless of the backend in use.

<!-- markdownlint-disable MD013 -->

| Name                      | Required | Default   | Description                                                                                                      |
| ------------------------- | -------- | --------- | ---------------------------------------------------------------------------------------------------------------- |
| dependency_manager        | False    | `auto`    | `auto`; `maven`, `gradle` or `cargo` (cyclonedx); `uv`, `pdm`, `poetry`, `pipenv`, `pip-tools` or `pip` (python) |
| untrusted_checkout        | False    | `auto`    | Is the checkout untrusted: `auto`, `true` or `false`                                                             |
| java_version              | False    | `21`      | JDK version for the cyclonedx backend                                                                            |
| java_distribution         | False    | `temurin` | JDK distribution for the cyclonedx backend                                                                       |
| maven_plugin_version      | False    | `2.9.3`   | `cyclonedx-maven-plugin` version; `2.8.0` or newer                                                               |
| maven_args                | False    | `''`      | Extra arguments appended to the Maven call, split on whitespace                                                  |
| gradle_plugin_version     | False    | `3.4.1`   | `cyclonedx-gradle-plugin` version; `3.0.0` or newer                                                              |
| gradle_version            | False    | `''`      | Gradle version the project uses; empty asks the build tool                                                       |
| gradle_args               | False    | `''`      | Extra arguments appended to the Gradle call, split on whitespace                                                 |
| cargo_cyclonedx_version   | False    | `0.5.9`   | `cargo-cyclonedx` version; `0.5.5` or newer                                                                      |
| cyclonedx_cli_version     | False    | `0.33.1`  | `cyclonedx-cli` version; writes the XML document for Cargo                                                       |
| cargo_target              | False    | `all`     | Cargo: `all` targets, or one target triple to describe                                                           |
| cargo_features            | False    | `''`      | Cargo: features to activate, separated by whitespace or commas; `package/feature` allowed                        |
| cargo_all_features        | False    | `false`   | Cargo: activate all features (`--all-features`)                                                                  |
| cargo_no_default_features | False    | `false`   | Cargo: do not activate default features (`--no-default-features`)                                                |
| cargo_working_directory   | False    | `''`      | Cargo: directory to run Cargo from, `path_prefix` or beneath it; empty runs it from `path_prefix`                |
| python_version            | False    | `3.12`    | Python for the python backend's tools and environment; `3.10` or newer                                           |
| cyclonedx_py_version      | False    | `7.5.0`   | `cyclonedx-bom` (`cyclonedx-py`) version for the python backend; `4.0.0` or newer                                |

<!-- markdownlint-enable MD013 -->

A declared `dependency_manager` must belong to the backend selected:
`uv` with `backend: cyclonedx` fails, as does `maven` with
`backend: python`. The `syft` backend ignores the input.
`cargo_working_directory` fails any run that drives no Cargo; see
[Cargo specifics](#cargo-specifics).

#### Choosing the build tool

Left at `auto`, the action reads the project directory: a `pom.xml`
selects Maven, a Gradle build script selects Gradle, and a `Cargo.toml`
selects Cargo. Where a tree carries more than one, the first in that
order wins: a tree carrying both a `pom.xml` and a Gradle build resolves
as Maven, and a Java project carrying a `Cargo.toml` for a native helper
stays a Java project.

Those mixed cases are guesses about intent, and a caller often knows
better.
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

#### Cargo specifics

The action runs the installed `cargo-cyclonedx` binary directly rather
than as `cargo cyclonedx`. Cargo resolves a subcommand through aliases
in the checkout's `.cargo/config.toml` and through `PATH`, so the
subcommand name could reach a different program. It always passes
`--format json` and the spec version explicitly, because the tool's
own defaults are XML and CycloneDX 1.3.

**Specification versions.** `cargo-cyclonedx` writes CycloneDX 1.3,
1.4 and 1.5, and no later version. Validation rejects any other
`sbom_spec_version` for Cargo, rather than letting the tool fail later.
The default, `1.5`, works. The action writes the XML document with
`cyclonedx-cli` from the finished JSON one, so both formats describe
the same document; measured against `cargo-cyclonedx`'s own XML, the
two differ in timestamp precision alone.

**Lockfiles.** A missing `Cargo.lock` gets resolved for the run, with
a warning, and removed afterwards; the SBOM then describes what
resolves today rather than what the project pinned. A **stale**
lockfile, one cargo would have to change, fails the run.
`cargo-cyclonedx` would otherwise rewrite it in the checkout without a
word (measured) and describe a graph no build of this commit uses, so
the action has `cargo metadata --locked` accept the lockfile first and
leaves it untouched.

**Targets.** `cargo_target: all`, the default, describes the
dependencies of every platform. `Cargo.lock` serves every platform,
and a crate ships to platforms the runner is not, so describing the
runner's alone would leave platform-specific dependencies unscanned. A
target triple narrows the document to that platform. The action
removes `CARGO_BUILD_TARGET` from the tool's environment, because
`cargo-cyclonedx` 0.5.9 lets it override `--target`, `all` included
(measured). The document records the choice in
`metadata.properties`, as `cdx:rustc:sbom:target:all_targets` or
`cdx:rustc:sbom:target:triple`.

**Features.** By default the document describes a build with default
features, so a dependency behind any other feature is missing from it,
and from any scan of it. Select the features the project ships with
through `cargo_features`, `cargo_all_features` and
`cargo_no_default_features`. They pass as `--features`,
`--all-features` and `--no-default-features` to `cargo-cyclonedx` and
to the `cargo metadata --locked` check of the lockfile before it, so
that check covers the graph the selection resolves, and an offline
cargo needs no sources outside that graph (measured). An input left at
its default adds no flag, so both calls stay as before. The action
normalises `cargo_features` to one comma-separated `--features`
argument. Each entry has to be a feature name, optionally qualified by
a package (`my-crate/tls`), matching what
[rust-build-action](https://github.com/lfreleng-actions/rust-build-action)
accepts, so one caller value works in both. Validation rejects
anything else, and either boolean outside `true`/`false`, without
repeating the value. The other dependency managers ignore all three, as
they do `cargo_target`. The job summary reports the selection; the
document itself does not record it.

`cargo-cyclonedx` hands the flags to `cargo metadata`, which resolves
them as `cargo build --workspace` with the same flags would
from the `path_prefix` directory, errors included. Measured against
`cargo-cyclonedx` 0.5.9 and cargo 1.90, on virtual and root-package
workspaces under resolvers 1 and 2, with `path_prefix` at the root and
at a member:

<!-- markdownlint-disable MD013 -->

| Selection                         | Applies to                                                              |
| --------------------------------- | ----------------------------------------------------------------------- |
| `cargo_features: tls`             | Every selected package that declares `tls`; the run fails if none does  |
| `cargo_features: my-crate/tls`    | `my-crate` alone, wherever `path_prefix` points                         |
| `cargo_no_default_features: true` | Every selected package                                                  |
| `cargo_all_features: true`        | Every feature of every member; supersedes the other two, as in cargo    |

<!-- markdownlint-enable MD013 -->

The selected packages are every workspace member, except under
resolver 1 when `path_prefix` holds a package, a root package or a
member, which selects that package alone. A feature the named or
selected packages lack fails the run with cargo's own error, rather
than describing a different build.

At a workspace root, the merged document then describes
`cargo build --workspace` with those features. With `path_prefix` at a
member of a resolver 2 workspace, the selection still spans the
workspace, since `cargo-cyclonedx` always resolves every member: cargo
accepts a feature that a sibling alone declares, where `cargo build`
inside the member would reject it, and the member's document reflects
whatever the selection does to the dependencies they share. To confine
a selection to one member, qualify each feature with its package name.

**Workspaces.** `cargo-cyclonedx` writes one document per workspace
member, beside each member's `Cargo.toml`, whichever manifest the
action names; it has no output directory option. The action gives those files
a random name, collects the ones it needs and removes the rest, so the
checkout ends as the run found it. What the SBOM describes depends on
where `path_prefix` points:

- **A single package**, outside any workspace or alone in one: its
  document as `cargo-cyclonedx` wrote it.
- **A workspace member**: that member's document alone. Sibling
  members it depends on appear as ordinary components, scoped
  `required`; their `path+file://` reference alone tells them apart from
  crates.io crates.
- **The workspace root**, a root package or a virtual workspace: every
  member's document merged into one.

The merged document takes the shape `cyclonedx-maven-plugin` gives a
reactor. `metadata.component` is a synthetic `library` named after the
workspace directory, with the reference `path+file://<workspace
root>`, and its `dependencies` entry carries **no** `dependsOn`. Each
member becomes a top-level component without a scope, keeping its own
`dependsOn`. Every other component keeps the scope `cargo-cyclonedx`
gave it, the strongest where members disagree, and `bom-ref` values
stay as cargo emits them, unaltered. A root that depended on its members
would put every crate a member declares one hop further from the
anchor, so a reader of the graph would take it for inherited.

Measured against `cargo-cyclonedx` 0.5.9:

<!-- markdownlint-disable MD013 -->

| Case                     | `dependencies` graph                     | Anchor                                                         |
| ------------------------ | ---------------------------------------- | -------------------------------------------------------------- |
| Single crate             | Full transitive edges                    | `metadata.component` (the crate); `dependsOn` its direct deps  |
| `path_prefix` at member  | Full transitive edges                    | That member; sibling members are components scoped `required`  |
| Workspace root (merged)  | Full, with each member's own edges       | Synthetic root without edges; members carry no scope           |

<!-- markdownlint-enable MD013 -->

In every shape each component has a `dependencies` entry, even one
without dependencies, and no edge names a missing reference. A
`bom-ref` is cargo's package ID, such as
`registry+https://github.com/rust-lang/crates.io-index#semver@1.0.28`
or `path+file:///<checkout>/core#name@0.1.0`, with the `purl`
(`pkg:cargo/semver@1.0.28`) alongside. Cargo targets nest under
their package as components and appear nowhere in the graph.
`metadata.tools` lists `cargo-cyclonedx` in the 1.4 form, a list, at
spec 1.5 too.

**Working directory.** Cargo reads `.cargo/config.toml`, and `rustup`
reads `rust-toolchain.toml`, from the directory it runs in and each
directory above it, not from the manifest. The action runs Cargo from
`path_prefix` by default, so with `path_prefix` at a workspace root a
configuration in a member directory does not apply. Where the build runs
Cargo from that member, a source replacement, `[patch]` or registry
setting there can then fail the lockfile check, or resolve a graph
other than the one the build used (measured). `cargo_working_directory`
runs Cargo from that directory instead, while `path_prefix` still
decides what the document describes:

```yaml
- uses: lfreleng-actions/sbom-action@<sha>
  with:
    backend: cyclonedx
    dependency_manager: cargo
    path_prefix: '.'
    cargo_working_directory: 'crates/cli'
```

Every Cargo call then runs from `crates/cli`: `cargo --version`,
`cargo locate-project`, `cargo generate-lockfile`, `cargo metadata` and
`cargo-cyclonedx`, and each one that reads a manifest names
`<path_prefix>/Cargo.toml` through `--manifest-path`. The value resolves
against `GITHUB_WORKSPACE` as `path_prefix` does, symlinks followed, and
has to name `path_prefix` itself or a directory beneath it. Validation
refuses anything else, and the action checks again at the point of
use, before running Cargo. Left empty, the default, Cargo runs from
`path_prefix` and every call stays as before.

The input applies to Cargo alone. Unlike the other `cargo_*` inputs, a
non-empty value fails a run with another backend or build tool rather
than going unused, because a caller who sets it expects the SBOM to
follow that directory's configuration. An untrusted checkout skips
before detecting a build tool, so there the backend and a declared
`dependency_manager` decide alone.

**Environment.** cargo and `cargo-cyclonedx` run without
`CARGO_REGISTRY_TOKEN`, any `CARGO_REGISTRIES_<NAME>_TOKEN`, the GitHub
OIDC request variables, `ACTIONS_RUNTIME_TOKEN`, or the paths of the
runner's command files (`GITHUB_OUTPUT`, `GITHUB_ENV`, `GITHUB_PATH`,
`GITHUB_STATE` and `GITHUB_STEP_SUMMARY`). Other registry settings,
such as `CARGO_REGISTRIES_<NAME>_INDEX`, stay, since resolution may
need them. That narrows what a rustc wrapper from the checkout can
reach, but remains defence in depth rather than a boundary: code running
as the same user can still read an ancestor process's environment and
find the command files at their predictable paths. The
[Trust Boundary](#trust-boundary) still applies.

#### Python specifics

**Detection.** Left at `auto`, the action reads `path_prefix` in
python-sbom-action's order, so a project resolves to the manager, and
reports the `dependency_manager` value, that it always did:

<!-- markdownlint-disable MD013 -->

| Order | Present in `path_prefix`                                          | `dependency_manager` | Installs from                                     |
| ----- | ----------------------------------------------------------------- | -------------------- | ------------------------------------------------- |
| 1     | `uv.lock`                                                         | `uv`                 | `uv.lock`                                         |
| 2     | `pdm.lock`                                                        | `pdm`                | `pdm.lock`                                        |
| 3     | `poetry.lock`                                                     | `poetry`             | `poetry.lock`                                     |
| 4     | `Pipfile.lock`                                                    | `pipenv`             | `Pipfile.lock`                                    |
| 5     | `requirements.txt` pinning with `==`, or beside `requirements.in` | `pip-tools`          | `requirements.txt`                                |
| 6     | `requirements.txt`                                                | `pip`                | `requirements.txt`                                |
| 7     | `pyproject.toml`                                                  | `pip`                | Its `[project]` dependencies                      |

<!-- markdownlint-enable MD013 -->

A declared value must find its file in `path_prefix`. Point
`path_prefix` at the directory holding the lock file: a uv or PDM
workspace member keeps no lock of its own, so it resolves as `pip`.

**Commands.** Each manager checks its lock against the manifest, then
installs:

<!-- markdownlint-disable MD013 -->

| Manager            | Lock check            | Install                                                     | `include_dev: 'true'`                                                             |
| ------------------ | --------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `uv`               | `uv lock --check`     | `uv sync --locked --no-install-project --no-default-groups` | Drops `--no-default-groups`: every group `default-groups` names, `dev` by default |
| `pdm`              | `pdm lock --check`    | `pdm sync --no-self --prod`                                 | Drops `--prod`: every development group                                           |
| `poetry`           | `poetry check --lock` | `poetry install --no-root`, main group alone                | Every non-optional group                                                          |
| `pipenv`           | `pipenv verify`       | `pipenv install --deploy`                                   | Adds `--dev`                                                                      |
| `pip-tools`, `pip` | none                  | `pip install -r requirements.txt`                           | Adds `-r requirements-dev.txt` and `--group dev`, each where present              |
| `pip` (pyproject)  | none                  | `pip install` the `[project]` dependencies                  | Adds `-r requirements-dev.txt` and `--group dev`, each where present              |

<!-- markdownlint-enable MD013 -->

None installs optional extras. A `pyproject.toml` whose dependencies are
`dynamic` stay unknown until its build backend runs, so for `pip` the
action builds and installs the project itself; pip builds it in place,
leaving `build/` and `*.egg-info` in the checkout as a build would.
Every other path leaves the checkout untouched.

**Lock files.** A lock that predates its manifest installs the previous
dependency set, and the SBOM would omit whatever the change under
review added — so a vulnerability scan would never see it. A stale
lock counts as a generation failure, as does any failed install:
under `fail_on_error: 'false'` the run warns and publishes nothing,
with `component_count` of `0`. The check runs explicitly for every
lock-file manager, because `pdm sync` exits 0 on a stale lock. For
`pip` there is no lock, and the action warns that the document
describes dependencies as they resolve today.

The environment's Python must also meet the project's
`requires-python`, or the run fails the same way: the managers check
it themselves, but a pip install of the declared dependencies does
not, and would skip without a word any dependency whose marker excludes
the wrong interpreter.

**The root component.** `cyclonedx-py` anchors the graph on a root
taken from `--pyproject`, whose `dependsOn` lists the project's direct
dependencies, so a reader can tell those from inherited ones. The
action passes a copy of the project's PEP 621 `[project]` table alone,
for two reasons measured on `cyclonedx-bom` 7.5.0:

- given the whole file, `cyclonedx-py` reads a `[tool.poetry]` table
  for the root's name, and fails with `KeyError: 'name'` on the
  ordinary Poetry 2 layout, where that table holds settings alone;
- it links the root to every installed package
  `[project.optional-dependencies]` names, so an extra installed solely
  because a development group also names it would read as a runtime
  dependency. The copy leaves optional dependencies out.

Dependencies that are `dynamic` come from the installed project's own
metadata instead, which `pip` has after building it. Either way the
action keeps each dependency whose environment marker holds for the
scanned interpreter with no extra selected, since `cyclonedx-py` links
the root by name alone and would otherwise take
`six; python_version < "3"` for a runtime dependency wherever something
else installed `six`. Where the project
is not installed — the lock-file managers leave it out — the root has
no edges, and the action warns. The project itself is never a
component, since it serves as the root.

Measured against the fixtures in `tests/fixtures/python`:

<!-- markdownlint-disable MD013 -->

| Project                                                  | `metadata.component`                    | Root `dependsOn`                                         |
| -------------------------------------------------------- | --------------------------------------- | -------------------------------------------------------- |
| PEP 621 `[project]`, any manager                         | The project, `bom-ref` `root-component` | Its runtime dependencies; development ones are not edges |
| `dynamic` dependencies, `pip`                            | The project                             | From the installed metadata                              |
| No `[project]` table (`Pipfile`, requirements, Poetry 1) | None, with a warning                    | —                                                        |

<!-- markdownlint-enable MD013 -->

Every component has a `dependencies` entry, `bom-ref` values take the
form `name==version`, and each component carries its `purl`
(`pkg:pypi/six@1.17.0`). Development dependencies appear as components
with no edge from the root, since the project does not depend on them
at runtime.

**Edges.** `cyclonedx-py` turns every dependency an installed
distribution declares into an edge, whatever its marker says, so
pluggy's `pytest; extra == "testing"` makes pluggy depend on pytest
wherever a development group installs pytest (measured, 7.5.0). The
action keeps an edge where the declaration applies, and nowhere else:
its marker holds for the scanned interpreter, with no extra selected or
with one requested of that distribution. The project takes part like
any other distribution, its requirements coming from its installed
metadata or, where uninstalled, from its `pyproject.toml`, optional
dependencies as the extras they are. Requested extras start from the
project (`requests[socks]` requests `socks` of requests) and follow
the edges that apply, including an extra a distribution requests of
itself (an `all` extra naming `pkg[http]`) and one a dependency
requests of the project. Everything the runtime graph does not reach,
development dependencies among it, keeps its own edges in a second
pass, whose extras never reach a runtime dependency: a development
tool requiring `requests[socks]` does not make PySocks a runtime
dependency of requests. The action does not follow extras that a
development group or requirements file requests directly, rather than
through an installed package, so it omits those extra-gated edges,
though the packages remain components. From CycloneDX 1.3, which
introduced component properties, the `required-extra` properties name
the extras resolved. Both finished documents must pass the CycloneDX
schema for `sbom_spec_version` before the action writes either. The
XML document comes from the same finished JSON one, by
`cyclonedx-python-lib`, which writes byte-for-byte the XML
`cyclonedx-py` does (measured, 1.5 and 1.6), so both formats carry
the same graph and serial number.

**Environment.** Three virtual environments under `RUNNER_TEMP` keep
the parts apart: one for the package manager and an up-to-date pip, one
for `cyclonedx-bom`, and one for the project's dependencies, created
without pip so that it holds those and nothing else. Every module the
action runs with `python -m` runs isolated (`python -I`), so a
checkout carrying `venv.py` or `pip.py` cannot replace the module it
names; the action's own helpers run as a package from the action's
directory (`python -E -s -m`), which keeps the checkout off the path.
Every command touching
the environment runs without
`PYTHONPATH` or `PYTHONHOME`, either of which would add whatever they
name to the document. The environment's own interpreter judges
markers, reporting its marker values run as `python -I -S` so
that no installed `.pth` file executes, rather than the action assuming
the interpreter it bound uv to. The action points
every manager at that last one — uv through `UV_PROJECT_ENVIRONMENT`, PDM
through `PDM_PYTHON`, ignoring any interpreter a committed
`.pdm-python` names, Poetry and Pipenv through the active virtual
environment — so the checkout gains no `.venv`. Lock checks, installs
and the scan run without the publishing credentials and runner
variables listed under [Cargo specifics](#cargo-specifics), and without
`TWINE_PASSWORD`, `UV_PUBLISH_TOKEN`, `UV_PUBLISH_PASSWORD`,
`PDM_PUBLISH_PASSWORD`, `FLIT_PASSWORD`, `HATCH_INDEX_AUTH` or any
`POETRY_PYPI_TOKEN_<NAME>`. Index settings such as `PIP_INDEX_URL`
stay, since resolution may need them. The same caveat holds: defence
in depth, not a boundary.

## Verification After Generation

A zero exit code from a backend does not by itself mean a usable
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

| Name               | Description                                                     |
| ------------------ | --------------------------------------------------------------- |
| sbom_json_path     | Path to generated JSON SBOM file                                |
| sbom_xml_path      | Path to generated XML SBOM file                                 |
| component_count    | Number of components in the generated SBOM                      |
| backend            | SBOM generation backend used                                    |
| dependency_manager | Build tool or package manager the backend drove                 |
| skipped            | `true` when the action declined to generate                     |
| image_count        | Image mode: number of images described                          |
| sboms_json         | Image mode: JSON array describing each image SBOM               |
| manifest_path      | Image mode: path to the manifest file                           |
| artifact_paths     | Image mode: newline-separated files written, manifest included  |

<!-- markdownlint-enable MD013 -->

The action emits `sbom_json_path` for the `json` and `both` formats,
and `sbom_xml_path` for the `xml` and `both` formats; the output for a
format the caller did not request stays empty.

In image mode there is no single document, so `sbom_json_path` and
`sbom_xml_path` stay empty and `component_count` reports the total
across every image. The four image-mode outputs stay empty in directory
mode. See [Container images](#container-images).

`dependency_manager` reports the build system the `cyclonedx` backend
drove, since the backend name identifies the tool rather than the build
system, or the package manager the `python` backend installed with. It
stays empty for `syft`.

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

Relative values for `path_prefix`, `cargo_working_directory`,
`image_archive_directory` and `output_directory` resolve against
`GITHUB_WORKSPACE`, not the current working directory, so behaviour
stays deterministic when a calling workflow sets a custom working
directory. The action checks the directory inputs against the runner
filesystem before use: `path_prefix` must resolve within
`GITHUB_WORKSPACE`, `cargo_working_directory` to `path_prefix` or a
directory beneath it, and
`image_archive_directory` and `output_directory` must resolve within
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
`includeTestScope` for Maven. Maven's `test` scope is the analogue of
npm `devDependencies`: absent from the running application, and so
excluded by default.

Gradle has configurations rather than scopes, so the mapping names them
directly. By default the backend scans `compileClasspath` and
`runtimeClasspath`; `include_dev` adds `testCompileClasspath` and
`testRuntimeClasspath`.

Naming them matters. Left unrestricted the plugin scans **every**
resolvable configuration, which pulls in tool classpaths such as
`jacocoAnt` and the ASM it carries — build tooling absent from the
shipped artefact, and noise in a vulnerability report. Measured against
the Gradle fixture: 6 components scoped, 24 unscoped.

**Custom configurations are not selectable.** The backend names
`compileClasspath` and `runtimeClasspath` (plus the test pair under
`include_dev`), and `gradle_args` cannot change that: the init script
assigns `includeConfigs` from that fixed list, and the action rejects
any `-DsbomAction.*` override. A project whose shipped dependencies
live in a configuration outside that set sees them absent from the
document rather than reported wrongly — so the count runs low rather
than misleading, though it remains incomplete. Selecting configurations
needs a dedicated input, which this action does not yet have.

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

**For Cargo, `include_dev` cannot include dev-dependencies.**
`cargo-cyclonedx` never records them, as neither component nor edge,
and offers no flag to include them (measured on 0.5.9). A Cargo SBOM
from this backend never describes `[dev-dependencies]`,
whatever `include_dev` says. A caller that needs them listed has no
route through this backend; the `syft` backend lists every locked
crate, unscoped.

What `include_dev` does control for Cargo is **build-dependencies**:
crates that build scripts run on the build machine, which never ship.
By default the action passes `--no-build-deps`, which drops them and
their edges. `include_dev: 'true'` keeps them, scoped `excluded`,
including the build-dependencies of dependencies (such as `cc` under a
`-sys` crate), and logs a warning that dev-dependencies stay absent. A
crate that is both a normal and a build dependency keeps the scope
`required` either way.

**For Python, `include_dev` selects what installs**, because
`cyclonedx-py` describes whatever the environment holds. Each manager's
own notion of a development dependency applies — every group uv's
`default-groups` names (`dev` unless the project says otherwise), PDM's
development groups, Poetry's non-optional groups, Pipenv's
`[dev-packages]`, and for pip a `requirements-dev.txt` or PEP 735 `dev`
group; see [Python specifics](#python-specifics) for the commands.
Development dependencies join the document as components, and never as
edges from the root: the project does not depend on them at runtime.
No component carries a CycloneDX `scope`, which `cyclonedx-py` leaves
unset.

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

## Container images

`mode: image` writes one SBOM per container image, reading docker
archives (`docker save` output) rather than a source tree. One
document per image, because a single SBOM cannot describe more than
one image, and a vulnerability finding has to name the image it
affects.

Image mode needs the `syft` backend, which is the default. Every
other input keeps its meaning: `sbom_format`, `sbom_spec_version`,
`filename_prefix`, `output_directory` and `fail_on_error` apply per
image, and `path_prefix` plays no part.

<!-- markdownlint-disable MD046 -->

```yaml
- name: "Download image archives"
  uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
  with:
    name: docker-archives
    path: ${{ runner.temp }}/docker-archives

- name: "Generate image SBOMs"
  id: sbom
  uses: lfreleng-actions/sbom-action@<sha>
  with:
    mode: image
    image_archive_directory: ${{ runner.temp }}/docker-archives
    sbom_format: json

- name: "Upload SBOM artifacts"
  uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
  with:
    name: sbom-files
    path: ${{ steps.sbom.outputs.artifact_paths }}
    if-no-files-found: error
```

<!-- markdownlint-enable MD046 -->

### The archive contract

The action scans every `*.tar` file directly inside
`image_archive_directory`, dot-prefixed names included, in byte
order. Each archive must hold
**a single** image, which is what
[docker-save-images-action](https://github.com/lfreleng-actions/docker-save-images-action)
writes in `per-image` mode. That action names each archive after the
image reference, with `/` and `:` mapped to `_`:
`ghcr.io/org/app:1.2` becomes `ghcr.io_org_app_1.2.tar`.

The archive's file name, minus `.tar`, is the image's **label**. Labels
must fit `A-Z a-z 0-9 . _ @ -`. A reference that action saves fits
that set unless its registry is an IPv6 address: the mapping leaves
the brackets of `[2001:db8::1]:5000/app:1.2` in the archive name, so
image mode refuses such archives. Push through a registry host name
instead.

The action checks each archive before scanning any of them, and fails
regardless of `fail_on_error` when one breaks the contract:

- an archive holding more than one image, which syft refuses to
  scan;
- a file that is not a complete docker archive: no `manifest.json`, or
  one whose `Config` and `Layers` the archive does not contain;
- a symbolic link, which could point the scan at any file on the
  runner;
- a label outside the character set above;
- an image reference in the archive (every `RepoTags` entry, not the
  first alone) that Docker's reference grammar rejects, such as
  `:justtag`.

These are configuration errors rather than generation errors: relaxing
them would publish SBOMs describing the wrong thing. A directory
holding no archives at all counts as a generation failure instead, and
honours `fail_on_error`, since a build permitted to fail can
legitimately leave nothing to scan.

### Filenames and the manifest

For each image the action writes `<filename_prefix>-<label>.json` (and
`.xml` where requested) into `output_directory`. With the default
prefix that is `sbom-cyclonedx-ghcr.io_org_app_1.2.json`, the name the
docker-workflows lanes have always produced, so a scanner globbing
`sbom-cyclonedx-*.json` finds every image document.

Alongside them it writes `<filename_prefix>.manifest.json`, an array
with one entry per image. The dot after the prefix keeps the manifest
outside that `sbom-cyclonedx-*.json` glob. The `sboms_json` output
carries the same array.

```json
[
  {
    "label": "ghcr.io_org_app_1.2",
    "image": "ghcr.io/org/app:1.2",
    "archive": "ghcr.io_org_app_1.2.tar",
    "format": "cyclonedx",
    "spec_version": "1.5",
    "sbom_json": "sbom-cyclonedx-ghcr.io_org_app_1.2.json",
    "sbom_xml": null,
    "component_count": 94
  }
]
```

<!-- markdownlint-disable MD013 -->

| Field             | Meaning                                                                       |
| ----------------- | ----------------------------------------------------------------------------- |
| `label`           | Archive file name minus `.tar`; the stable key in every filename              |
| `image`           | Image reference recorded in the archive's `manifest.json`; `null` if untagged |
| `archive`         | Archive file name                                                             |
| `format`          | Document standard, always `cyclonedx` today                                   |
| `spec_version`    | CycloneDX specification version of the documents                              |
| `sbom_json`       | JSON document, relative to the manifest; `null` when not requested            |
| `sbom_xml`        | XML document, relative to the manifest; `null` when not requested             |
| `component_count` | Components in this image's document                                           |

<!-- markdownlint-enable MD013 -->

`image` comes from the archive itself, not from reversing the filename
mapping, which cannot be undone: `a/b:1` and `a_b:1` both map to
`a_b_1`. A consumer naming images in a report should read `image`
rather than reconstruct it from a filename.

Paths in the manifest are relative to the manifest's own directory, so
it stays valid after an artifact upload and download. The
`manifest_path` output gives its location in the generating job, and
`artifact_paths` lists every file the run wrote, manifest included, for
`actions/upload-artifact`. Uploading that list rather than a glob
leaves out anything else sitting in the output directory.
Upload-artifact reads each line as a glob pattern, so in image mode
`output_directory`, once resolved, must not contain line breaks or any
of `* ? [ ] \`; the action refuses it rather than list a path that
would select other files. Upload-artifact also skips a file whose name
starts with `.` unless the caller enables `include-hidden-files`, so
image mode refuses a `filename_prefix` starting with `.`.

Each document names the image as its subject
(`metadata.component.name`). Left to itself syft would record the
archive's path on the runner there instead.

### Failure handling

Each document passes the same verification as directory mode. Any
failure fails the whole run, and the action removes every document and
the manifest it wrote: a partial set would pass a downstream glob as a
complete one. Under `fail_on_error: false` the step succeeds with
`image_count` and `component_count` of `0` and `sboms_json` of `[]`.

The action clears its destinations before generating, as in directory
mode, with the same guard against removing files it cannot identify.
It replaces a manifest when the file is a non-empty array whose
entries carry the fields above and no others.
It owns the names derived from the archives present and the manifest.
A document left over from an image the current run does not include
stays put, so point `output_directory` at a fresh directory, or upload
`artifact_paths`, where earlier output might linger.

### Specification version

The action asks syft for the version in `sbom_spec_version` (default
`1.5`). A bare `cyclonedx-json` output instead takes syft's own
default, which moves with syft releases: syft 1.51.1, the version the
pinned installer fetches, writes `1.7`. Set `sbom_spec_version` to
match a consumer that needs a particular version.

### Image references

Image mode reads docker archives and nothing else. Pulling from a
registry needs credentials and registry egress on every runner, and
reading the Docker daemon works in the job that built the images and
no other. The reusable workflows pass images between jobs as
archives, which leaves neither source available to them. To scan a
registry image directly,
[grype-scan-action](https://github.com/lfreleng-actions/grype-scan-action)
accepts a `registry:` target.

## Migrating from python-sbom-action

The `python` backend replaces
[python-sbom-action](https://github.com/lfreleng-actions/python-sbom-action).
Every input that action took keeps its name, meaning and default here
(`python_version`, `include_dev`, `sbom_format`, `sbom_spec_version`,
`filename_prefix`, `output_directory`, `path_prefix` and
`fail_on_error`), and so does every output (`sbom_json_path`,
`sbom_xml_path`, `component_count` and `dependency_manager`, with the
same manager names). Switching takes a different `uses:` and a
`backend` input:

<!-- markdownlint-disable MD046 -->

```yaml
- name: "Generate SBOM"
  id: sbom
  uses: lfreleng-actions/sbom-action@<sha>
  with:
    backend: python
    # Where this job holds nothing an earlier job running the same
    # checkout lacked; see Untrusted checkouts
    untrusted_checkout: 'false'
    path_prefix: ${{ inputs.path_prefix }}
    include_dev: ${{ inputs.sbom_include_dev }}
    sbom_format: ${{ inputs.sbom_format }}
```

<!-- markdownlint-enable MD046 -->

What changes:

- **Untrusted checkouts skip.** python-sbom-action ran on any
  checkout. Here `untrusted_checkout: 'auto'` skips a fork pull
  request; see [Untrusted checkouts](#untrusted-checkouts). A workflow
  passes `'false'` where its SBOM job holds no permissions, secrets or
  runner beyond those of an earlier job that ran the same checkout.
- **A soft failure publishes nothing.** Under `fail_on_error: 'false'`
  python-sbom-action warned about a stale lock or failed install and
  generated anyway, from whatever had installed. Here the run warns,
  writes no document and reports `component_count: 0`, as every
  backend does: a partial SBOM reads as a clean scan. A project with no
  Python files at all fails whatever `fail_on_error` says. The default,
  `'true'`, fails as before.
- **Counts fall.** `cyclonedx-bom`'s own dependency tree, which
  python-sbom-action installed into the environment it scanned, no
  longer appears, so `component_count` drops by that much.
- **The document has a root.** `metadata.component` names the project
  wherever `pyproject.toml` carries a `[project]` table, and its
  `dependsOn` lists the direct dependencies.
- **A project carrying `pyproject.toml` alone** gets an SBOM of its
  dependencies, not of the runner's Python.
- **Paths stay confined.** Relative `path_prefix` and `output_directory`
  values resolve against `GITHUB_WORKSPACE` rather than the working
  directory, must stay within the workspace (or `RUNNER_TEMP` for the
  output), and `filename_prefix` takes `A-Z a-z 0-9 . _ -` alone. See
  [Path Constraints](#path-constraints).
- **The job's Python stays untouched.** python-sbom-action left the
  Python it installed on `PATH` for the steps after it; this action
  does not change `PATH`.

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

1. **Input Validation**: Validates backend, mode, format, boolean flags, specification version, filename prefix, and the `java_version`, `java_distribution`, `maven_plugin_version`, `gradle_plugin_version`, `gradle_version`, `dependency_manager`, `untrusted_checkout`, `cargo_cyclonedx_version`, `cyclonedx_cli_version`, `cargo_target`, `cargo_features`, `cargo_all_features`, `cargo_no_default_features`, `python_version` and `cyclonedx_py_version` inputs against restricted value sets before use, including that a declared `dependency_manager` belongs to the selected backend; verifies the project directory exists, or in image mode the archive directory, and that any `cargo_working_directory` lies within the project directory on a run that drives Cargo; and rejects image mode with any backend but `syft` and an archive directory set without image mode. `maven_args` and `gradle_args` are **not** constrained this way — the action splits each on whitespace and rejects them solely for selecting an alternate project or overriding action-owned properties, leaving them trusted input (see [Inputs](#inputs)). For the `cyclonedx` and `python` backends this step also resolves the trust decision and the build system or package manager, failing fast on a project it cannot drive before installing any toolchain; for `cyclonedx` it skips a Gradle version below the plugin's floor where the caller supplied one, and for Cargo requires `cargo` on `PATH` and a specification version `cargo-cyclonedx` can write
2. **Toolchain Setup**: For the `syft` backend, fetches the syft binary via the pinned `anchore/sbom-action/download-syft` helper action. For the `cyclonedx` backend, installs a JDK via the pinned `actions/setup-java` for Maven and Gradle, or for Cargo installs `cargo-cyclonedx` (and `cyclonedx-cli` for XML output) via the pinned `taiki-e/install-action`. For the `python` backend, installs Python via the pinned `actions/setup-python` without changing the job's environment. The selected backend and build tool guard each step, so none costs anything when unused
3. **SBOM Generation**: A single step dispatches on the backend, and the `cyclonedx` backend dispatches again on the build system. The `syft` backend runs one scan emitting the requested CycloneDX formats (`format@version=path` syntax). For Maven, the action invokes `cyclonedx-maven-plugin`'s `makeAggregateBom` goal directly, writing into the resolved output directory. For Gradle, an init script applies `cyclonedx-gradle-plugin` and runs `cyclonedxBom`, configuring the task destinations once Gradle finishes evaluating the consumer's build scripts, so that a consumer's own configuration cannot displace them. For Cargo, the action checks the lockfile with `cargo metadata --locked`, runs `cargo-cyclonedx` under a scrubbed environment, merges the per-member documents of a workspace with `jq`, and converts the result to XML with `cyclonedx-cli` where requested. For Python, the action installs the package manager and `cyclonedx-bom` into environments of their own, checks the lock, installs the project's dependencies into a third environment, anchors the root on the project's `[project]` table, runs `cyclonedx-py environment` against that environment once, then gives every component the edges whose declaration applies, checks the result against the schema and writes both formats from that one document. In every case the JSON document always gets generated internally to compute the component count. In image mode the step instead checks every archive against the contract, then runs one syft scan per archive (`docker-archive:` source, `--source-name` set to the image reference, or the label for an untagged image), verifies each document, and writes the manifest
4. **Outputs and Summary**: Emits output paths for the requested formats, the component count, the build tool used, and a step summary, which for Cargo names the feature selection; in image mode, the image count, manifest, its path, and the list of files written

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
  toolchain. The `cyclonedx` and `python` backends necessarily give up
  that property: resolving a Maven dependency graph requires Maven, a
  Cargo one requires cargo, and describing a Python environment
  requires installing it
- For Python projects, use `backend: python`. Its environment-based
  generation describes what the resolver actually installed, with
  markers applied, and anchors the graph on the project; the `syft`
  backend reads lock files without either
- For Java projects, use `backend: cyclonedx` rather than the default. The
  `syft` backend will produce an SBOM for a Maven project, but one that
  omits transitive dependencies and reports BOM-managed versions as
  `UNKNOWN`
- Image mode replaces the inline "Generate image SBOMs" step of the
  docker-workflows build lanes. With `sbom_format: json` it writes the
  same `sbom-cyclonedx-<label>.json` names, so the lanes' artifact and
  Grype scan need no change. The documents differ from the inline
  step's in timestamp, serial number and subject name, plus the
  specification version unless `sbom_spec_version` is `1.7`
- Image mode refuses archives outside the workspace and `RUNNER_TEMP`,
  so a lane downloading archives to `/tmp` must move them under
  `${{ runner.temp }}` first

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/sbom-action/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/sbom-action/main.svg
