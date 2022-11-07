# InSpec Scanning Integration

This repository holds sample templates for running InSpec profiles in Gitlab CI pipelines. You can reference these templates in other projects' `gitlab.ci` files. For general information on Gitlab templates see the [documentation](https://docs.gitlab.com/ee/development/cicd/templates.html).

These templates were designed for _testing the InSpec profiles themselves_ against hardened and unhardened test systems (both containerized and cloud VM systems) to ensure they produce accurate scan results. They may serve as a jumping-off point for running InSpec in a Gitlab pipeline more generally.

## Templates

The templates are located in the `./inspec-scanning-integration/templates` directory.

### Check Template

The `check-template.yml` is a template that runs the `inspec check` command to verify the InSpec profile is properly formatted. 

### Lint Template

The `lint-template.yml` is a template that lints the `/controls` directory's Ruby code.

### Dependencies Template

The `dependencies.yml` is a template that consolidates all templates into one file that can be imported by other projects. 

## Invoking Templates - Example

You will need to [mirror this repository](https://docs.gitlab.com/ee/user/project/repository/mirror/) inside your own Gitlab instance to make it visible to your other projects.

Reference these templates in the `gitlab.ci` file in your InSpec profile repository.

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

This Gitlab pipeline will use the templates to test your InSpec code against both containers and EC2 VMs.

### Test Kitchen

Note that InSpec is invoked by way of Progress Chef's [Test Kitchen](https://docs.chef.io/workstation/kitchen/). Your InSpec profile should have some YAML files for configuring Kitchen.

Ex. kitchen.dokken.yml:
``` yaml
---
provisioner:
  name: dummy

platforms:
  - name: rhel7

driver:
  name: dokken
  pull_platform_image: false

transport:
  name: dokken

verifier:
  input_files:
    - container.inputs.yml
  reporter:
    - cli
    - json:reports/raw/container-%{suite}-%{platform}.json

suites:
  - name: vanilla
    driver:
      image: <%= ENV['VANILLA_CONTAINER_IMAGE'] %>
  - name: hardened
    driver:
      image: <%= ENV['HARDENED_CONTAINER_IMAGE'] %>

```

And kitchen.ec2.yml:
``` yaml
---
platforms:
  - name: rhel-7

driver:
  name: ec2
  aws_ssh_key_id: <%= ENV['AWS_SSH_KEY_ID'] %>
  user_data: ./user_data.sh
  tags:
    POC: <%= ENV['POC_TAG'] %>
  security_group_ids: <%= ENV['SECURITY_GROUP_IDS'] %>
  region: <%= ENV['AWS_REGION'] %>
  subnet_id: <%= ENV['SUBNET_ID'] %>
  instance_type: t2.large
  associate_public_ip: true

transport:
  name: ssh
  username: <%= ENV['AWS_EC2_USER'] %>
  ssh_key: <%= ENV['AWS_EC2_SSH_KEY'] %>
  connection_timeout: 10
  connection_retries: 5

verifier:
  input_files:
    - ec2.inputs.yml
  reporter:
    - cli
    - json:reports/raw/ec2-%{suite}-%{platform}.json

lifecycle:
  post_create:
    - remote: |
        sudo yum -y install python3-pip
        sudo python3 -m pip install --upgrade pip

  pre_converge:
    - remote: |
        echo "NOTICE - Updating the ec2-user to keep sudo working"
        sudo chage -d $(( $( date +%s ) / 86400 )) ec2-user
        echo "NOTICE - updating ec2-user sudo config"
        sudo chmod 600 /etc/sudoers && sudo sed -i'' "/ec2-user/d" /etc/sudoers && sudo chmod 400 /etc/sudoers

suites:
  - name: vanilla
    driver:
      image_id: <%= ENV['AMI_ID'] %>
    provisioner:
      name: ansible_playbook
      playbook: test/ansible/rhel7STIG-ansible/vanilla.yml

  - name: hardened
    driver:
      image_id: <%= ENV['AMI_ID'] %>
    provisioner:
      name: ansible_playbook
      playbook: test/ansible/rhel7STIG-ansible/site.yml

```

If Kitchen does not discover all of the config data it needs to execute in the file you specify, it will fill in the blanks using the default `kitchen.yml` file. So in the above case, where we want to run a pipeline that targets both containers and VMs, we would put variables that are common between both (such as the `verifier`, which is always going to be the InSpec profile we are trying to test) in a file called `kitchen.yml` that should also live at the root of your profile directory.

``` yaml
transport:
  name: ssh
  max_ssh_sessions: 2

verifier:
  name: inspec
  sudo: true
  reporter:
    - cli
    - json:reports/raw/%{suite}-%{platform}.json
  inspec_tests:
    - name: RedHat Enterprise Linux 7 STIG
      path: .
  load_plugins: true

provisioner:
  name: ansible_playbook
  hosts: all
  require_ansible_repo: true
  require_chef_for_busser: false
  require_ruby_for_busser: false
  ansible_verbose: true
  roles_path: test/ansible/rhel7STIG-ansible/roles

suites:
  - name: vanilla
  - name: hardened
```

### CI/CD Variables

Note the Kitchen files include syntax to reference [CI/CD variables](https://docs.gitlab.com/ee/ci/variables/) set in the Gitlab repository settings (ex. `image_id: <%= ENV['AMI_ID'] %>`). CI/CD variables are copied over to the Gitlab runner as environment variables during pipeline execution. Ensure that data which should remain secret (*especially your AWS config*) are stored as CI/CD variables; do not commit them as code.

## Gitlab CI/CD Variables

These templates expect certain environment variables to be available to the Gitlab Runner, which can be done most easily by setting them as CI/CD variables in the project that will include the templates.

## Required Variables List

- REGISTRY: The private registry link that you will use to store pipeline container images, ex. `https://your.registry.org`
- INSPEC_RUNNER_IMAGE_ID: The container ID of an image containing the InSpec executable. Tested with `chef/chefworkstation`.
- INSPEC_RUNNER_IMAGE_TAG: The tag of the image containing the InSpec executable, ex. `latest`.

## Debugging

Run the pipeline with a CI/CD variable `DEBUG=true` to run each step of the Test Kitchen execution in order instead of all at once (the default behavior of running `kitchen test`).