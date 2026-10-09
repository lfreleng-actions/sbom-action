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
for Java projects, where static analysis falls short. See
[Backends](#backends) for how to choose between them.

The `mode` input chooses what the document describes: a project
directory (the default), or one SBOM per container image from docker
archives. See [Container images](#container-images).

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

| Backend          | Tool                         | Build tools driven   | Needs a toolchain                   | Use for                                 |
| ---------------- | ---------------------------- | -------------------- | ----------------------------------- | --------------------------------------- |
| `syft` (default) | syft static analysis         | none                 | No                                  | Go, Node.js, Rust, containers, binaries |
| `cyclonedx`      | CycloneDX build-tool plugins | Maven, Gradle, Cargo | JDK + build tool, or Rust toolchain | Java and Rust projects                  |

<!-- markdownlint-enable MD013 -->

`cyclonedx-gradle-plugin` is the same tool family solving the same
problem as `cyclonedx-maven-plugin`, so Gradle joins the **existing**
`cyclonedx` backend rather than arriving as a separate one, and so does
`cargo-cyclonedx` for Rust. Callers keep the same `backend` value, and
the action resolves the build system from the project unless the caller
declares it.

Because the backend name does not identify the build system, the
`dependency_manager` output reports which one ran (`maven`, `gradle` or
`cargo`).
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

No command-line flag turns any of that off, and for Maven it happens
even though the goal never compiles source or runs tests. A project
supplying a core extension, a build script, a wrapper or a cargo
configuration thus executes code in the job.

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
The action pins no toolchain: cargo runs from the project directory,
where the project's `rust-toolchain.toml` applies and `rustup` may
install the toolchain it names. A caller wanting a particular toolchain
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

## Inputs

<!-- markdownlint-disable MD013 -->

| Name                    | Required | Default          | Description                                                                              |
| ----------------------- | -------- | ---------------- | ---------------------------------------------------------------------------------------- |
| backend                 | False    | `syft`           | SBOM generation backend: `syft` or `cyclonedx`                                           |
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

### CycloneDX backend inputs

These apply when `backend` is `cyclonedx`, but the action validates
them on every run so a typo surfaces regardless of the backend in use.

<!-- markdownlint-disable MD013 -->

| Name                    | Required | Default   | Description                                                      |
| ----------------------- | -------- | --------- | ---------------------------------------------------------------- |
| dependency_manager      | False    | `auto`    | Build tool: `auto`, `maven`, `gradle` or `cargo`                 |
| java_version            | False    | `21`      | JDK version for the cyclonedx backend                            |
| java_distribution       | False    | `temurin` | JDK distribution for the cyclonedx backend                       |
| maven_plugin_version    | False    | `2.9.3`   | `cyclonedx-maven-plugin` version; `2.8.0` or newer               |
| maven_args              | False    | `''`      | Extra arguments appended to the Maven call, split on whitespace  |
| gradle_plugin_version   | False    | `3.4.1`   | `cyclonedx-gradle-plugin` version; `3.0.0` or newer              |
| gradle_version          | False    | `''`      | Gradle version the project uses; empty asks the build tool       |
| gradle_args             | False    | `''`      | Extra arguments appended to the Gradle call, split on whitespace |
| cargo_cyclonedx_version | False    | `0.5.9`   | `cargo-cyclonedx` version; `0.5.5` or newer                      |
| cyclonedx_cli_version   | False    | `0.33.1`  | `cyclonedx-cli` version; writes the XML document for Cargo       |
| cargo_target            | False    | `all`     | Cargo: `all` targets, or one target triple to describe           |
| untrusted_checkout      | False    | `auto`    | Is the checkout untrusted: `auto`, `true` or `false`             |

<!-- markdownlint-enable MD013 -->

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

| Name               | Description                                                     |
| ------------------ | --------------------------------------------------------------- |
| sbom_json_path     | Path to generated JSON SBOM file                                |
| sbom_xml_path      | Path to generated XML SBOM file                                 |
| component_count    | Number of components in the generated SBOM                      |
| backend            | SBOM generation backend used                                    |
| dependency_manager | Build tool the `cyclonedx` backend drove                        |
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

Relative values for `path_prefix`, `image_archive_directory` and
`output_directory` resolve against `GITHUB_WORKSPACE`, not the current
working directory, so behaviour stays deterministic when a calling
workflow sets a custom working directory. The action checks the
directory inputs against the runner filesystem before use:
`path_prefix` must resolve within `GITHUB_WORKSPACE`, and
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

1. **Input Validation**: Validates backend, mode, format, boolean flags, specification version, filename prefix, and the `java_version`, `java_distribution`, `maven_plugin_version`, `gradle_plugin_version`, `gradle_version`, `dependency_manager`, `untrusted_checkout`, `cargo_cyclonedx_version`, `cyclonedx_cli_version` and `cargo_target` inputs against restricted value sets before use; verifies the project directory exists, or in image mode the archive directory, and rejects image mode with any backend but `syft` and an archive directory set without image mode. `maven_args` and `gradle_args` are **not** constrained this way — the action splits each on whitespace and rejects them solely for selecting an alternate project or overriding action-owned properties, leaving them trusted input (see [Inputs](#inputs)). For the `cyclonedx` backend this step also resolves the trust decision and the build system, failing fast on one it cannot drive before installing any toolchain, skips a Gradle version below the plugin's floor where the caller supplied one, and for Cargo requires `cargo` on `PATH` and a specification version `cargo-cyclonedx` can write
2. **Toolchain Setup**: For the `syft` backend, fetches the syft binary via the pinned `anchore/sbom-action/download-syft` helper action. For the `cyclonedx` backend, installs a JDK via the pinned `actions/setup-java` for Maven and Gradle, or for Cargo installs `cargo-cyclonedx` (and `cyclonedx-cli` for XML output) via the pinned `taiki-e/install-action`. The selected backend and build tool guard each step, so none costs anything when unused
3. **SBOM Generation**: A single step dispatches on the backend, and the `cyclonedx` backend dispatches again on the build system. The `syft` backend runs one scan emitting the requested CycloneDX formats (`format@version=path` syntax). For Maven, the action invokes `cyclonedx-maven-plugin`'s `makeAggregateBom` goal directly, writing into the resolved output directory. For Gradle, an init script applies `cyclonedx-gradle-plugin` and runs `cyclonedxBom`, configuring the task destinations once Gradle finishes evaluating the consumer's build scripts, so that a consumer's own configuration cannot displace them. For Cargo, the action checks the lockfile with `cargo metadata --locked`, runs `cargo-cyclonedx` under a scrubbed environment, merges the per-member documents of a workspace with `jq`, and converts the result to XML with `cyclonedx-cli` where requested. In every case the JSON document always gets generated internally to compute the component count. In image mode the step instead checks every archive against the contract, then runs one syft scan per archive (`docker-archive:` source, `--source-name` set to the image reference, or the label for an untagged image), verifies each document, and writes the manifest
4. **Outputs and Summary**: Emits output paths for the requested formats, the component count, the build tool used, and a step summary; in image mode, the image count, manifest, its path, and the list of files written

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
  resolving a Maven dependency graph requires Maven, and a Cargo one
  requires cargo
- For Python projects, prefer
  [python-sbom-action](https://github.com/lfreleng-actions/python-sbom-action):
  its environment-based generation gives higher-fidelity results for
  resolved Python dependency graphs
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
