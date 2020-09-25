# encoding: UTF-8

control 'TCAT-AS-001550' do
    title 'Tomcat server must be patched for security vulnerabilities.'
    desc  'Tomcat is constantly being updated to address newly discovered
    security vulnerabilities. If the Tomcat server is not updated to address these
    risks, the server could be compromised or a new DoS attack could be successful.'
    desc  'rationale', ''
    desc  'check', '
      Refer to https://tomcat.apache.org/security-9.html and identify the latest
    secure version of Tomcat with no known vulnerabilities.
  
      As a privileged user from the Tomcat server, run the following command:
  
      sudo $CATALINA_HOME/bin/version.sh |grep -i server
  
      Compare the version running on the system to the latest secure version of
    Tomcat.
  
      If the latest secure version of Tomcat is not installed, this is a finding.
    '
    desc  'fix', '
      Follow operational procedures for upgrading Tomcat. Download latest version
    of Tomcat and install in a test environment. Test applications that are running
    in production and follow all operations best practices when upgrading the
    production Tomcat application servers.
  
      Update the Tomcat production instance accordingly and ensure corrected
    builds are installed once tested and verified.
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000456-AS-000266'
    tag gid: 'TCAT-AS-001550'
    tag rid: 'TCAT-AS-001550_rule'
    tag stig_id: 'TCAT-AS-001550'
    tag fix_id: 'F-TCAT-AS-001550_fix'
    tag cci: ['CCI-002605']
    tag nist: ['SI-2 c']

    describe "This is a manual check" do 
        skip "Compare the output version of $CATALINA_HOME/bin/version.sh on the system with the latest secure version of Tomcat.
        If the latest available secure version of Tomcat is not installed. This is a finding."
    end
  
end