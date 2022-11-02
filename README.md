# InSpec Scanning Integration

This repository holds templates for Gitlab CI pipelines. You can reference these templates in other projects' `gitlab.ci` files. For general information on Gitlab templates see the [documentation](https://docs.gitlab.com/ee/development/cicd/templates.html).

## Templates

The templates are located in the `./inspec-scanning-integration/templates` directory.

### Check Template

The `check-template.yml` is a template that runs the `inspec check` command to verify the InSpec profile is properly formated 

### Lint Template

The `lint-template.yml` is a template that lints the `/controls` directory. The controls directory contains source code for evaluating STIGs.

### Dependencies Template

The `dependencies.yml` is a template that consolidates all templates into one file that can be imported by other projects. 

## Invoking Templates - Example

In the `gitlab.ci` file in a separate project in your Gitlab that you want to have reference these templates:

``` yaml
include:
  - project: project/path/to/inspec-scanning-integration
    ref: "main" # branch name of this repo you want to include
    file: templates/templates.yml

stages:
  - verify

kitchen-exec-container:
  extends: .ci:stage:kitchen-exec:inspec
  variables: # overwrite default variables in the template if necessary
    KITCHEN_LOCAL_YAML: "kitchen.dokken.yml"

kitchen-exec-ec2:
  extends: .ci:stage:kitchen-exec:inspec
  variables:
    KITCHEN_LOCAL_YAML: "kitchen.ec2.yml"

verify:
  extends: .ci:stage:saf:verify
  dependencies:
    - kitchen-exec-ec2
    - kitchen-exec-container
```

This Gitlab pipeline will use the templates to test your InSpec code against a container and an ec2.