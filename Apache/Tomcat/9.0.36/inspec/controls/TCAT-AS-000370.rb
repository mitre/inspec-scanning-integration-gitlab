# encoding: UTF-8

control 'TCAT-AS-000370' do
    title 'Files in the $CATALINA_HOME/conf/ folder must have their permissions
    set to 640.'
    desc  'Tomcat file permissions must be restricted. The standard configuration
    is to have all Tomcat files owned by root with group Tomcat. While root has
    read/write privileges, group only has read permissions, and world has no
    permissions. The exceptions are the logs, temp, and work directories that are
    owned by the Tomcat user group tomcat rather than root user group tomcat. This
    means that even if an attacker compromises the Tomcat process, they cannot
    change the Tomcat configuration, deploy new web applications, or modify
    existing web applications. The Tomcat process runs with a umask of 0027 to
    maintain these permissions.'
    desc  'rationale', ''
    desc  'check', '
      Access the Tomcat server from the command line and execute the following OS
    command:
  
      sudo find $CATALINA_HOME/conf/* -follow -maxdepth 0 -type f \\( \\! -perm
    640 \\) -ls
  
      If no files are displayed, this is not a finding.
  
      If results indicate any of the file permissions contained in the
    $CATALINA_HOME/conf folder are not set to 640, this is a finding.
    '
    desc  'fix', '
      Run the following command on the Tomcat server:
  
      sudo find $CATALINA_HOME/conf/* -follow -maxdepth 0 -type f -print0 | sudo
    xargs chmod 640 $CATALINA_HOME/conf/*
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000119-AS-000079'
    tag gid: 'TCAT-AS-000370'
    tag rid: 'TCAT-AS-000370_rule'
    tag stig_id: 'TCAT-AS-000370'
    tag fix_id: 'F-TCAT-AS-000370_fix'
    tag cci: ['CCI-000163']
    tag nist: ['AU-9']

    tomcat_conf_dir = command("ls /usr/local/tomcat/conf").stdout.split
    tomcat_conf_dir.each do |web_file|
        describe command("stat -c %a /usr/local/tomcat/conf/#{web_file}") do
            its('stdout.strip') { should cmp 640 }
        end
    end  
end