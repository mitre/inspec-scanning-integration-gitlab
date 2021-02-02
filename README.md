# InSpec Scanning Integration

This repository holds templates and dockerfiles for CI pipelines. All SCV_Content repositories build on these templates and dockerfiles.

## Templates

The templates are located in the `./inspec-scanning-integration/templates` directory.

### Check Template

The `check-template.yml` is a template that runs the `inspec check` command to verify the InSpec profile is properly formated 

### Lint Template

The `lint-template.yml` is a template that lints the `/controls` directory. The controls directory contains source code for evaluating STIGS.

### Dependencies Template

The `dependencies.yml` is a template that conolidates all templates into one file that can be imported by other projects. 

## Dockerfiles

The Dockerfiles are located in the `./inspec-scanning-integration/dockerfiles` directory. 

### Rubocop

Rubocop is an open-source project used to perform static code analysis and linting for community-driven best practices for structuring Ruby code. 

Build instructions: 
- Assumes the machine is set up with Docker. 
- Syntax: `docker build -t <REGISTRY>/<IMAGE_NAME>[:TAG] .`.

```
$ cd inspec_scanning-integration/dockerfiles/rubocop
$ docker build -t repo.dsolab.io/ci/rubocop:v0.88 .
```

### Cookstyle 

Rubocop is a project created by Chef.io and is used to validate Chef generated artifacts 

Build instructions: 
- Assumes the machine is set up with Docker. 
- Syntax: `docker build -t <REGISTRY>/<IMAGE_NAME>[:TAG] .`.

```
$ cd inspec_scanning-integration/dockerfiles/cookstyle
$ docker build -t repo.dsolab.io/ci/cookstyle:7.7.2 .
```
