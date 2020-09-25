# encoding: UTF-8

control 'TCAT-AS-001470' do
    title 'Tomcat server must be patched for security vulnerabilities.'
    desc  'Tomcat is constantly being updated to address newly discovered
    vulnerabilities some of which include Denial-of-Service attacks. To address
    this risk, the Tomcat admin must ensure the system remains up to date on
    patches.'
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
    tag gtitle: 'SRG-APP-000435-AS-000163'
    tag gid: 'TCAT-AS-001470'
    tag rid: 'TCAT-AS-001470_rule'
    tag stig_id: 'TCAT-AS-001470'
    tag fix_id: 'F-TCAT-AS-001470_fix'
    tag cci: ['CCI-002385']
    tag nist: ['SC-5']
    
    describe "This is a manual check" do 
        skip "Compare the output version of $CATALINA_HOME/bin/version.sh on the system with the latest secure version of Tomcat.
        If the latest available secure version of Tomcat is not installed. This is a finding."
    end

end