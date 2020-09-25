# encoding: UTF-8

control 'TCAT-AS-001270' do
    title '$CATALINA_HOME/temp folder permissions must be set to 750.'
    desc  'Tomcat\'s file permissions must be restricted. The standard
    configuration is to have all Tomcat files owned by root with the group Tomcat.
    While root has read/write privileges, tomcat group only has read and world has
    no permissions. The exceptions are the logs, temp and work directory that are
    owned by the Tomcat user rather than root. This means that even if an attacker
    compromises the Tomcat process, they cannot change the Tomcat configuration,
    deploy new web applications, or modify existing web applications. The Tomcat
    process runs with a umask of 007 to maintain these permissions.'
    desc  'rationale', ''
    desc  'check', '
      Access the Tomcat server from the command line and execute the following OS
    command:
  
      sudo find $CATALINA_HOME/temp -follow -maxdepth 0 -type d \\( \\! -perm 750
    \\) -ls
  
      If no folders are displayed, this is not a finding.
  
      If results indicate the $CATALINA_HOME/temp folder permissions are not set
    to 750, this is a finding.
    '
    desc  'fix', '
      Run the following commands on the Tomcat server:
  
      sudo find  $CATALINA_HOME/temp -follow -maxdepth 0 -type d -print0 | sudo
    xargs chmod 750 $CATALINA_HOME/temp
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000380-AS-000088'
    tag gid: 'TCAT-AS-001270'
    tag rid: 'TCAT-AS-001270_rule'
    tag stig_id: 'TCAT-AS-001270'
    tag fix_id: 'F-TCAT-AS-001270_fix'
    tag cci: ['CCI-001813']
    tag nist: ['CM-5 (1)']
    
    tomcat_temp_dir = file("/usr/local/tomcat/temp")
    describe tomcat_temp_dir do 
        its("mode") { should cmp "750" }
    end

end