# InSpec Scanning Integration

This repository holds templates for CI pipelines. All SCV_Content repositories build on these templates and dockerfiles.

## Templates

The templates are located in the `./inspec-scanning-integration/templates` directory.

### Check Template

The `check-template.yml` is a template that runs the `inspec check` command to verify the InSpec profile is properly formated 

### Lint Template

The `lint-template.yml` is a template that lints the `/controls` directory. The controls directory contains source code for evaluating STIGS.

### Dependencies Template

The `dependencies.yml` is a template that conolidates all templates into one file that can be imported by other projects. 


