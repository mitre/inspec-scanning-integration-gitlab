## Gitlab Pipeline Image

The
[`pipeline_writer`](https://gitlab.dsolab.io/applications-and-tools/pipeline_writer)
project  has it's own Gitlab pipeline to ensure new changes to the project do
not introduce breaking changes into existing functionality.

## Pipeline Information

Details about the pipeline

### Image
The image used for the pipeline is the current stable release of Rust (1.50.0)
which can be found **[here](https://hub.docker.com/_/rust)**. The image is taken
from the **Docker Official Images** repository. The official Rust image is then
enhanced with a cargo crate called `cargo-tarpaulin`. 

**[Tarpaulin](https://crates.io/crates/cargo-tarpaulin)** is a tool to determine code coverage achieved via cargo tests. The test coverage badge in the main README.md for this project is derived from the percentage output from Tarpaulin.

### Stages
The pipeline stages for this project are check, lint, test, build, and release.

* Check: Check stage has one job that uses the built in `cargo check` command to check the local
    project and it's dependencies for errors. 
* Lint: Lint stage has one job that checks the formatting of the project using
    the cargo component rustfmt. The project is then linted by the cargo
    component clippy which includes over 400 linting rules.
* Test: The Test stage has two jobs defined. 
  - test_writer job performs the built in `cargo test` command to ensure all
      tests are passing. 
  - test_coverage job uses the Tarpaulin application to calculate the code
      coverage percentage. Gitlab has a feature to apply a coverage badge to
      projects. A regex is used (/\d+.\d+% coverage/) to parse the Tarpaulin
      report. 
* Bulid: The build stage has one job that runs the built-in `cargo build
    --release` command to create a binary from a Rust project. The '--release'
    flag is used to eliminate debugging information from the binary. This will
    create a smaller binary which makes the application smaller and more
    performant. 
* Release: The release stage is available when a tag is introduced to the Gitlab
    pipeline. The binary that was created from the 'Build' stage is pushed into
    the Dsolab group's Nexus raw-hosted **[repository](https://rep.dsolab.io)**. This binary will then be
    available to other projects that depend on this application by downloading
    the binary from Nexus. The format for the release url used is
    https://[HOST]/[REPO_NAME]/pipeline_writer/[RELEASE_TAG]/writer.
    A structure was defined in case other projects need to pull
    a new release of the application. 

## Building
Steps for building the Docker image 

Build an image
```
$ git clone https://gitlab.dsolab.io/applications-and-tools/pipeline_writer.git
$ cd pipeline_writer/.gitlab
$ docker build -t writer:1.0.0 .
```

