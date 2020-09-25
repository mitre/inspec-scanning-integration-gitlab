# encoding: UTF-8

control 'TCAT-AS-001060' do
    title 'Tomcat user account must be a non-privileged user.'
    desc  '
      Use a distinct non-privileged user account for running Tomcat. If Tomcat
    processes are compromised and a privileged user account is used to operate the
    Tomcat server processes, the entire system becomes compromised.
  
      Sample passwd file:
      tomcat:x:1001:1001::/opt/tomcat/usr/sbin/nologin
  
      The user ID is stored in field 3 of the passwd file.
    '
    desc  'rationale', ''
    desc  'check', '
      Run the following command to identify the Tomcat process UID:
      ps -ef | { head -1; grep catalina; } | cut -f1 -d\' \'
  
      Run the following command to obtain the OS user ID tied to the Tomcat
    process:
      cat /etc/passwd|grep -i <UID>|cut -f3 -d:
  
      If the user ID field of the passwd file is set to < 1000 or = 0, this is a
    finding.
    '
    desc  'fix', '
      From the Tomcat server, create a tomcat user by adding a new non-privileged
    user OS account with the following command:
  
      sudo useradd tomcat
  
      Edit the systemd tomcat.service file or create one if it does notexist. Use
    the new \'tomcat\' user account by setting; USER=tomcat
  
      Location of the file should be /etc/systemd/system/tomcat.service
  
      Enable the Tomcat service:
      sudo restorecon /etc/systemd/system/tomcat.service
      sudo chmod 644 /etc/systemd/system/tomcat.service
      sudo systemctl enable tomcat.service
  
      Start Tomcat:
      sudo systemctl start tomcat
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000340-AS-000185'
    tag gid: 'TCAT-AS-001060'
    tag rid: 'TCAT-AS-001060_rule'
    tag stig_id: 'TCAT-AS-001060'
    tag fix_id: 'F-TCAT-AS-001060_fix'
    tag cci: ['CCI-002235']
    tag nist: ['AC-6 (10)']

    passwd = command("cat /etc/passwd | grep -i tomcat")
    if passwd.exit_status == 0
        tomcat_user_id = passwd.stdout.strip.split(":")[2].to_i 
        describe tomcat_user_id do 
            it { should_not be < 1000 }
        end 
    else
        describe passwd do 
            its('exit_status') { should cmp 0 }
        end
    end

end