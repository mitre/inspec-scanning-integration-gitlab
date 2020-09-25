# encoding: UTF-8

control 'TCAT-AS-001250' do
    title '$CATALINA_HOME/logs/ folder must be owned by tomcat user, group
    tomcat.'
    desc  'Tomcat file permissions must be restricted. The standard configuration
    is to have all Tomcat files owned by root with group Tomcat. While root has
    read/write privileges, group only has read permissions, and world has no
    permissions. The exceptions are the logs, temp, and work directories that are
    owned by the Tomcat user rather than root. This means that even if an attacker
    compromises the Tomcat process, they cannot change the Tomcat configuration,
    deploy new web applications, or modify existing web applications. The Tomcat
    process runs with a umask of 007 to maintain these permissions.'
    desc  'rationale', ''
    desc  'check', '
      Access the Tomcat server from the command line and execute the following OS
    command:
  
      sudo find $CATALINA_HOME/logs -follow -maxdepth 0 \\(  ! -user tomcat -o !
    -group tomcat \\) -ls
  
      If no folders are displayed, this is not a finding.
  
      If results indicate the $CATALINA_HOME/logs folder ownership and group
    membership is not set to tomcat:tomcat, this is a finding.
    '
    desc  'fix', '
      Run the following commands on the Tomcat server:
  
      sudo find $CATALINA_HOME/logs -maxdepth 0 \\( ! -user tomcat \\) | sudo
    xargs chown tomcat
  
      sudo find $CATALINA_HOME/logs -maxdepth 0 \\( ! -group tomcat \\) | sudo
    xargs chgrp tomcat
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000380-AS-000088'
    tag gid: 'TCAT-AS-001250'
    tag rid: 'TCAT-AS-001250_rule'
    tag stig_id: 'TCAT-AS-001250'
    tag fix_id: 'F-TCAT-AS-001250_fix'
    tag cci: ['CCI-001813']
    tag nist: ['CM-5 (1)']

    tomcat_log_dir = file("/usr/local/tomcat/logs")
    describe tomcat_log_dir do 
        its('owner') { should cmp 'tomcat' }
        its('group') { should cmp 'tomcat' }
    end 

end