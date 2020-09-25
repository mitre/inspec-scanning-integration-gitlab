# encoding: UTF-8

control 'TCAT-AS-001220' do
    title '$CATALINA_HOME/conf/ folder must be a owned by root,  group tomcat.'
    desc  'Tomcat file permissions must be restricted. The standard configuration
    is to have Tomcat files contained in the conf/ folder as members of the
    \'tomcat\' group. While root has read/write privileges, group only has read
    permissions, and world has no permissions. The exceptions are the logs, temp,
    and work directories that are owned by the Tomcat user rather than root. This
    means that even if an attacker compromises the Tomcat process, they cannot
    change the Tomcat configuration, deploy new web applications, or modify
    existing web applications. The Tomcat process runs with a umask of 007 to
    maintain these permissions. Note that running Tomcat in a Docker environment
    can impact how file permissions and user ownership settings are applied. Due to
    associated Docker configuration complexities, the STIG is scoped for standalone
    rather than virtual Docker deployments.'
    desc  'rationale', ''
    desc  'check', '
      Access the Tomcat server from the command line and execute the following OS
    command:
  
      sudo find $CATALINA_HOME/conf -follow -maxdepth 0 \\(  ! -user root -o !
    -group tomcat \\) -ls
  
      If no folders are displayed, this is not a finding.
  
      If results indicate the $CATALINA_HOME/conf folder ownership and group
    membership is not set to root:tomcat, this is a finding.
    '
    desc  'fix', '
      Run the following commands on the Tomcat server:
  
      sudo find $CATALINA_HOME/conf -maxdepth 0 \\( ! -user root \\) | sudo xargs
    chown root
  
      sudo find $CATALINA_HOME/conf -maxdepth 0 \\( ! -group tomcat \\) | sudo
    xargs chgrp tomcat
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000380-AS-000088'
    tag gid: 'TCAT-AS-001220'
    tag rid: 'TCAT-AS-001220_rule'
    tag stig_id: 'TCAT-AS-001220'
    tag fix_id: 'F-TCAT-AS-001220_fix'
    tag cci: ['CCI-001813']
    tag nist: ['CM-5 (1)']
    
    tomcat_conf_dir = file("/usr/local/tomcat/conf")
    describe tomcat_conf_dir do 
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'tomcat' }
    end 

end