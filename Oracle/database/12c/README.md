## ORACLE 12c STIG Automated Compliance Validation Profile
<b>Oracle Database</b> Version 12c <b>12.2.0.1</b>

<b>Oracle 12c</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>Oracle databse</b>.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>Oracle Database</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## Oracle database STIG Overview

The <b>Oracle Database</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>Oracle Database</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the Oracle Database STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

This check provides guidance on the configuration of <b>Oracle Database</b> to address requirements associated with:

### This STIG Automated Compliance Validation Profile was developed based upon:
- Oracle Database 12c Security Technical Implementation Guide
- CIS Oracle Database 19c Benchmark
- Database Security Requirements Guide.

## Getting Started

### Requirements

To run the <b>Oracle </b> STIG Compliance Validation Program.

#### Database Host  
- Oracle 12c database image. 
- Remote access to Oracle Database Server or Container.
- Minimum 8GB memory to execute Oracle 12c Database container.
- Minimum 80GB storage supporting Oracle 12c Database container.
- Account providing appropriate permissions to perform audit scan.

#### STIG Validation Execution Host 
- Linux VM or Host
- sudo access to install packages

#### Required software on STIG Validation Execution Host 
- git
- ssh
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on STIG Validation Execution Host 
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for you Operating System to download and install InSpec.
Goto Go to https://docs.docker.com/get-docker/ and consult the documentation for your Operating System to download and install Docker.

#### Ensure your InSpec version is at least 4.23.10 
```sh
inspec --version
```

### Setting inputs in inspec.yml 

For more information on different options with inputs, refer to: https://docs.chef.io/inspec/inputs/

### Configuring the inputs in your inputs.yml file
```yaml
# description: Username Oracle DB (e.g., 'system')
user: ''

# description: Password Oracle DB (e.g., 'xvIA7zonxGM=1')
password: ''

# description: Hostname Oracle DB (e.g., 'localhost')
host: ''

# description: Service name Oracle DB (e.g., 'ORCLCDB')
service: ''

# description: Location of sqlplus tool (e.g., '/opt/oracle/product/12.2.0.1/dbhome_1/bin/sqlplus')
sqlplus_bin: ''

# description: Set to true if standard auditing is used
standard_auditing_used: false 

# description: Set to true if unified auditing is used
unified_auditing_used: false

# description: List of allowed database links
allowed_db_links: []

# description: List of allowed database admins
allowed_dbadmin_users: []

# description: List of users allowed access to PUBLIC
users_allowed_access_to_public: []

# description: List of users allowed the dba role
allowed_users_dba_role: []

# description: List of users allowed the system tablespace
allowed_users_system_tablespace: []

# description: List of application owners
allowed_application_owners: []

# description: List of allowed unlocked Oracle db accounts
allowed_unlocked_oracledb_accounts: []

# description: List of users allowed access to the dictionary table
users_allowed_access_to_dictionary_table: []

# description: List of users allowed admin privileges
allowed_users_with_admin_privs: []

# description: List of users allowed audit access
allowed_audit_users: []

# description: List of allowed dba object owners
allowed_dbaobject_owners: []

# description: List of allowed Oracle db components
allowed_oracledb_components: []

# description: List of Oracle db components allowed to be intregrated into the dbms
allowed_oracledb_components_integrated_into_dbms: []

# description: List of allowed Oracle dba's
oracle_dbas: []
```
### How to execute this instance  
(See: https://www.inspec.io/docs/reference/cli/)

#### Execute a single Control in the Profile 
**Note**: replace the profile's directory name - e.g. - `<Profile>` with `.` if you are in the profile's root directory.
```sh
inspec exec <Profile>/controls/V-61965.rb --input user=<auditaccount> password=<auditaccountpassword> host=<containerid> service=<OracleSID> sqlplus_bin=<sqlpluslocation> standard_auditing_used=<true/false> unified_auditing_used=<true/false> users_allowed_access_to_dictionary_table=true -t docker://<name_of_container> --show-progress
```
or use the `--controls` flag
```sh
inspec exec <Profile> --controls=V-61965 V-68863 --input user=<auditaccount> password=<auditaccountpassword> host=<containerid> service=<OracleSID> sqlplus_bin=<sqlpluslocation> standard_auditing_used=<true/false> unified_auditing_used=<true/false> users_allowed_access_to_dictionary_table=true -t docker://<name_of_container> --show-progress
```

#### Execute a Single Control and save results as JSON 
```sh
inspec exec <Profile> --controls=V-61965 --input user=<auditaccount> password=<auditaccountpassword> host=<containerid> service=<OracleSID> sqlplus_bin=<sqlpluslocation> standard_auditing_used=<true/false> unified_auditing_used=<true/false> users_allowed_access_to_dictionary_table=true -t docker://<name_of_docker_container> --show-progress --reporter json:results.json
```

#### Execute All Controls in the Profile 
```sh
inspec exec <Profile>--input user=<auditaccount> password=<auditaccountpassword> host=<containerid>  service=<OracleSID> sqlplus_bin=<sqlpluslocation> -t docker://Oracle19c --show-progres
```

#### Execute all the Controls in the Profile and save results as JSON 
```sh
inspec exec <Profile> --input user=<auditaccount> password=<auditaccountpassword> host=<containerid>  service=<OracleSID> sqlplus_bin=<sqlpluslocation> unified_auditing_used=<true/false> -t docker://Oracle19c --show-progres  --reporter json:results.json
```