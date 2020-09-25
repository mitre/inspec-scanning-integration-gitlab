# encoding: UTF-8

control 'TCAT-AS-000560' do
    title 'Example applications must be removed.'
    desc  'Tomcat provides example applications, documentation, and other
    directories in the default installation which do not serve a production use.
    These files must be deleted.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server OS type the following command:
  
      sudo ls -l $CATALINA_HOME/webapps/examples.
  
      If the examples folder exists or contains any content, this is a finding.
    '
    desc  'fix', '
      From the Tomcat server OS type the following command:
  
       sudo rm -rf $CATALINA_HOME/webapps/examples
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000141-AS-000095'
    tag gid: 'TCAT-AS-000560'
    tag rid: 'TCAT-AS-000560_rule'
    tag stig_id: 'TCAT-AS-000560'
    tag fix_id: 'F-TCAT-AS-000560_fix'
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']

    describe command("ls -l $CATALINA_HOME/webapps/examples") do
        its('stdout.strip') { should eq '' }
    end
end