# encoding: UTF-8

control 'TCAT-AS-001050' do
    title 'Tomcat user account must be set to nologin.'
    desc  'When installing Tomcat, a user account is created on the OS. This
    account is used in order for Tomcat to be able to operate on the OS but does
    not require the ability to actually log in to the system. Therefore when the
    account is created, the account must not be provided access to a login shell or
    other program on the system. This is done by specifying the \'nologin\'
    parameter in the command/shell field of the passwd file.'
    desc  'rationale', ''
    desc  'check', '
      From the command line of the Tomcat server type the following command:
  
      sudo cat /etc/passwd|grep -i tomcat
  
      If the command/shell field of the passwd file is not set to
    \'/usr/sbin/nologin\', this is a finding.
    '
    desc  'fix', '
      From the Tomcat command line type the following command:
  
      sudo usermod -s /usr/sbin/nologin tomcat
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000340-AS-000185'
    tag gid: 'TCAT-AS-001050'
    tag rid: 'TCAT-AS-001050_rule'
    tag stig_id: 'TCAT-AS-001050'
    tag fix_id: 'F-TCAT-AS-001050_fix'
    tag cci: ['CCI-002235']
    tag nist: ['AC-6 (10)']

    output = command("cat /etc/passwd | grep -i tomcat")
    if output.exit_status == 0
        nologin = output.stdout.strip.split(":")[-1]
        describe nologin do 
            it { should cmp "/usr/sbin/nologin" }
        end 
    else 
        describe output do 
            its('exit_status') { should cmp 0 }
        end
    end

end