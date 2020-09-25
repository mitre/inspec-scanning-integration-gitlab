# Security Scanning 
This repository contains STIG scanning content used in conjunction with the Chef InSpec tool.
 
* inspec profiles

#### Organization
This repository is structured according to the following rules:
```
  vendor
  -->technology 
     --> version 
        --> inpsec
```

For example:
```
   Apache
      Httpd
        2.4x
           inspec
      Tomcat
        9.0.36
           inspec
```

#### Scanner Pipeline
This project includes a `Jenkinsfile` and  `rubocop` build artifacts that assists Jenkins in scanning the repository for InSpec profile comliance. The steps below outline the various stages that a performed.  

Pipeline Steps:  

1. Lint Profiles:  
- Each profile contains multiple Ruby files within the `controls/` directory that InSpec tests against a target. Rubocop is a static code analyzer following the community Ruby Style Guide. Each profile is linted to ensure compliance with best practices.  

2. InSpec profile compliance and report generation per Profile  
- The InSpec `check` command analyzes the inspec profiles which are the `inspec/` directories in this project. This step ensures each profile is in the right format for inspec to test against a target.  
- Conditional step on `check`:  
   - If the `inspec check` command fails then the  `inspec exec` command will fail and produce a non-functional report for logstash. To avoid this situation happening the return status of the `inspec check` command is used to tell the pipeline if `inspec exec` should run or not.  

3. Send reports to Logstash  
- Placeholder step for when ELK is up and running in the support environment  

4. Cleanup Workspace  
- Removes generated reports.    
