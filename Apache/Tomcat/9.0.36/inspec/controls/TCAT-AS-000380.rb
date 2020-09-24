# encoding: UTF-8

control 'TCAT-AS-000380' do
    title 'Jar files in the $CATALINA_HOME/bin/ folder must have their
    permissions set to 640.'
    desc  'Tomcat\'s file permissions must be restricted. The standard
    configuration is to have all Tomcat files owned by root with the group Tomcat.
    While root has read/write privileges, tomcat group only has read permissions,
    and world has no permissions. The exceptions are the logs, temp, and work
    directories that are owned by the Tomcat user rather than root. This means that
    even if an attacker compromises the Tomcat process, they cannot change the
    Tomcat configuration, deploy new web applications, or modify existing web
    applications. The Tomcat process runs with a umask of 007 to maintain these
    permissions.'
    desc  'rationale', ''
    desc  'check', '
      Access the Tomcat server from the command line and execute the following OS
    command:
  
      sudo find $CATALINA_HOME/bin/*jar -follow -maxdepth 0 -type f  \\( \\!
    -perm 640 \\) -ls
  
      If there are no results, or if .sh extensions are found, this is not a
    finding.
  
      If results indicate any of the jar file permissions contained in the
    $CATALINA_HOME/bin folder are not set to 640, this is a finding.
    '
    desc  'fix', '
      Run the following command on the Tomcat server:
  
      sudo find $CATALINA_HOME/bin/*jar -follow -maxdepth 0 -type f -print0 |
    sudo xargs chmod 640 $CATALINA_HOME/bin/*jar
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000120-AS-000080'
    tag gid: 'TCAT-AS-000380'
    tag rid: 'TCAT-AS-000380_rule'
    tag stig_id: 'TCAT-AS-000380'
    tag fix_id: 'F-TCAT-AS-000380_fix'
    tag cci: ['CCI-000164']
    tag nist: ['AU-9']
    
    tomcat_jar_dir = command("find /usr/local/tomcat/bin/*jar").stdout.split
    tomcat_jar_dir.each do |jar|
        describe command("stat -c %a #{jar}") do
            its('stdout.strip') { should cmp 640 }
        end
    end  

end