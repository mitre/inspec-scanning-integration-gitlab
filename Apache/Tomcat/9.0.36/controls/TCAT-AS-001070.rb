# encoding: UTF-8

control 'TCAT-AS-001070' do
    title '$CATALINA_HOME/bin folder permissions must be set to 750.'
    desc  'Tomcat file permissions must be restricted. The standard configuration
    is to have all Tomcat files owned by root with group Tomcat. While root has
    read/write privileges, group only has read permissions, and world has no
    permissions. The exceptions are the logs, temp, and work directories that are
    owned by the Tomcat user rather than root. This means that even if an attacker
    compromises the Tomcat process, they cannot change the Tomcat configuration,
    deploy new web applications, or modify existing web applications. The Tomcat
    process runs with a umask of 007 to maintain these permissions. Note that
    running Tomcat in a Docker environment can impact how file permissions and user
    ownership settings are applied. Due to associated Docker configuration
    complexities, the STIG is scoped for standalone rather than virtual Docker
    deployments.'
    desc  'rationale', ''
    desc  'check', '
      Access the Tomcat server from the command line and execute the following OS
    command:
  
      sudo find $CATALINA_HOME/bin -follow -maxdepth 0 -type d \\( \\! -perm 750
    \\) -ls
  
      If no folders are displayed, this is not a finding.
  
      If results indicate the $CATALINA_HOME/bin folder permissions are not set
    to 750, this is a finding.
    '
    desc  'fix', '
      Run the following command on the Tomcat server:
  
      sudo find  $CATALINA_HOME/bin -follow -maxdepth 0 -type d -print0 | sudo
    xargs chmod 750 $CATALINA_HOME/bin
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000340-AS-000185'
    tag gid: 'TCAT-AS-001070'
    tag rid: 'TCAT-AS-001070_rule'
    tag stig_id: 'TCAT-AS-001070'
    tag fix_id: 'F-TCAT-AS-001070_fix'
    tag cci: ['CCI-002235']
    tag nist: ['AC-6 (10)']
    
    tomcat_bin_dir = file("/usr/local/tomcat/bin")
    describe tomcat_bin_dir do 
        its('mode') { should cmp '750' }
    end
    
end