# encoding: UTF-8

control 'V-102575' do
  title 'Tomcat server must be patched for security vulnerabilities.'
  desc  "Tomcat is constantly being updated to address newly discovered
vulnerabilities, some of which include denial-of-service attacks. To address
this risk, the Tomcat administrator must ensure the system remains up to date
on patches.


  "
  desc  'rationale', ''
  desc  'check', "
    Refer to https://tomcat.apache.org/security-9.html and identify the latest
secure version of Tomcat with no known vulnerabilities.

    As a privileged user from the Tomcat server, run the following command:

    sudo $CATALINA_HOME/bin/version.sh |grep -i server

    Compare the version running on the system to the latest secure version of
Tomcat.

    If the latest secure version of Tomcat is not installed, this is a finding.
  "
  desc  'fix', "
    Follow operational procedures for upgrading Tomcat. Download latest version
of Tomcat and install in a test environment. Test applications that are running
in production and follow all operations best practices when upgrading the
production Tomcat application servers.

    Update the Tomcat production instance accordingly and ensure corrected
builds are installed once tested and verified.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag satisfies: ['SRG-APP-000435-AS-000163', 'SRG-APP-000456-AS-000266']
  tag gid: 'V-102575'
  tag rid: 'SV-111515r1_rule'
  tag stig_id: 'TCAT-AS-001470'
  tag fix_id: 'F-108107r1_fix'
  tag cci: ['CCI-002385', 'CCI-002605']
  tag nist: ['SC-5', 'SI-2 c']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  server_version = command("#{catalina_base}/bin/version.sh | grep -i 'Server version' ").stdout.strip
  built_date = command("#{catalina_base}/bin/version.sh | grep -i 'Server built' ").stdout.strip
  
  describe "The Tomcat administrator must ensure the system remains up to date on patches" do 
    skip "The version and date of the this server is:\n#{server_version}\n#{built_date}\nCompare the version running on the system to the latest secure version of Tomcat. If the latest secure version of Tomcat 
    is not installed, this is a finding"
  end

end

