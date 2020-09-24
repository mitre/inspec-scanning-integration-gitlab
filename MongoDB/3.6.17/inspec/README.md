# mongodb-enterprise-advanced-stig-baseline

InSpec profile to validate the secure configuration of MongoDB Enterprised Advanced 3, against [DISA](https://iase.disa.mil/stigs/)'s **MongoDB Enterprise Advanced 3.x Security Technical Implementation Guide (STIG) Version 1, Release 1**.

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Running This Profile

    inspec exec https://github.com/mitre/mongodb-enterprise-advanced-stig-baseline/archive/master.tar.gz -t ssh://<hostip> --user '<admin-account>' --password=<password> --reporter cli json:<filename>.json

Runs this profile over ssh to the host at IP address <hostip> as a privileged user account (i.e., an account with administrative privileges), reporting results to both the command line interface (cli) and to a machine-readable JSON file. 
    
    inspec exec https://github.com/mitre/mongodb-enterprise-advanced-stig-baseline/archive/master.tar.gz -t ssh://<hostip> --user '<admin-account>' --password=<password> --reporter cli json:<filename>.json
    
Runs this profile over ssh to the host at IP address hostip as a privileged user account (i.e., an account with administrative privileges), reporting results to both the command line interface (cli) and to a machine-readable JSON file.

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://mitre.github.io/heimdall-lite/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __full heimdall server__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
- Alicia Sturtevant

## Special Thanks

- The MITRE InSpec Team

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/mongodb-enterprise-advanced-stig-baseline/issues/new).

For other help, please send a message to [inspec@mitre.org](mailto:inspec@mitre.org).

To contribute, please review the [contribution guidelines](https://github.com/mitre/docs-mitre-inspec/blob/master/CONTRIBUTING.md).

## License 

This project is licensed under the terms of the [Apache 2.0 license](https://github.com/mitre/mongodb-enterprise-advanced-stig-baseline/blob/master/LICENSE.md).

### NOTICE

© 2019 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx   

