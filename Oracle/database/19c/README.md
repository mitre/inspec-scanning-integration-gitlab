## ORACLE 19c STIG Automated Compliance Validation Profile
<b>Oracle Database</b> Version 19c <b>19.3.0.0.0</b>

<b>Oracle 19c</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>Oracle databse</b>.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>Oracle Database</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## Oracle database STIG Overview

The <b>Oracle Database</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>Oracle Database</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the Oracle Database STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

This check provides guidance on the configuration of <b>Oracle Database</b> to address requirements associated with:

<b>[List out technology specific requirements]</b>

### This STIG Automated Compliance Validation Profile was developed based upon:
- Oracle Database 12c Security Technical Implementation Guide
- CIS Oracle Database 19c Benchmark
- Database Security Requirements Guide.

## Getting Started

### Requirements

To run the <b>Oracle </b> STIG Compliance Validation Program......<b>[insert startup requirements]</b>

#### Database Host  <b>[update or remove section based upon technology]</b>
- Kubernetes cluster containing Oracle 19c image executing in a docker container.
- Remote access to Oracle Database Server or Container.
- Minimum 8GB memory to execute Oracle 19c Database container.
- Minimum 80GB storage supporting Oracle 19c Database container.
- Account providing appropriate permissions to perform audit scan.

#### STIG Validation Execution Host <b>[update or remove section based upon technology]</b>
- Linux VM or Host
- sudo access to install packages

#### Required software on STIG Validation Execution Host <b>[update or remove section based upon technology]</b>
- git
- ssh
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on STIG Validation Execution Host <b>[update or remove section based upon technology]</b>
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for you Operating System to download and install InSpec.
Goto Go to https://docs.docker.com/get-docker/ and consult the documentation for your Operating System to download and install Docker.

#### Ensure your InSpec version is at least 4.23.10 <b>[update or remove section based upon technology]</b>
```sh
inspec --version
```
### How to execute this instance  <b>[update or remove section based upon technology]</b>
(See: https://www.inspec.io/docs/reference/cli/)

#### Execute a single Control in the Profile <b>[update or remove section based upon technology]</b>
**Note**: replace the profile's directory name - e.g. - `<Profile>` with `.` if you are in the profile's root directory.
```sh
inspec exec <Profile>/controls/V-61965.rb -t docker://<name_of_container>
```
or use the `--controls` flag
```sh
inspec exec <Profile> --controls=V-61965 V-68863 -t docker://<name_of_docker_container>
```

#### Execute a Single Control and save results as HTML <b>[update or remove section based upon technology]</b>
```sh
inspec exec <Profile> --controls=V-61965 -t docker://<name_of_docker_container> --reporter json:results.json
```

#### Execute All Controls in the Profile <b>[update or remove section based upon technology]</b>
```sh
inspec exec <Profile> -t docker://<name_of_docker_container>
```

#### Execute all the Controls in the Profile and save results as HTML <b>[update or remove section based upon technology]</b>
```sh
inspec exec <Profile> -t docker://<name_of_docker_container> --reporter json:results.json
```

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/



## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)