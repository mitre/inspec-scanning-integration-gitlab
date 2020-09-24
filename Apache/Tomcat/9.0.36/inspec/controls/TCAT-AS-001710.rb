# encoding: UTF-8

control 'TCAT-AS-001710' do
    title 'Hosted applications must be documented in the system security plan.'
    desc  'The system administrator must be cognizant of all applications
    operating on the Tomcat server, and must address any security implications
    associated with the operation of the applications.'
    desc  'rationale', ''
    desc  'check', '
      Review the Tomcat servers System Security Plan/server documentation.
  
      Access the Tomcat server and review the $CATALINA_HOME/webapps folder and
    the $CATALINA_BASE/webapps folder (if they exist).
  
      Ensure that all webapps are documented in the SSP.
  
      If the applications that are hosted on the Tomcat server are not documented
    in the SSP, this is a finding.
    '
    desc  'fix', '
      Document the applications that have an ATO on the Tomcat server.
  
      Retain the information in the SSP and present to the auditor in the event
    of a CCRI.
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000516-AS-000237'
    tag gid: 'TCAT-AS-001710'
    tag rid: 'TCAT-AS-001710_rule'
    tag stig_id: 'TCAT-AS-001710'
    tag fix_id: 'F-TCAT-AS-001710_fix'
    tag cci: ['CCI-000366']
    tag nist: ['CM-6 b']

    describe "This is a manual check" do 
        skip "Document applications that have an ATO on the Tomcat server in the SSP"
    end 

end