# encoding: UTF-8

control 'TCAT-AS-000500' do
    title 'Unapproved connectors must be disabled.'
    desc  'Connectors are how Tomcat receives requests, passes them to hosted web
    applications, and then sends back the results to the requestor. Tomcat provides
    HTTP and Apache JServ Protocol (AJP) connectors and makes these protocols
    available via configured network ports. Unapproved connectors provide open
    network connections to either of these protocols and puts the system at risk.'
    desc  'rationale', ''
    desc  'check', '
      Review SSP for list of approved connectors and associated TCP/IP ports.
    Ensure only approved connectors are present. Execute the following command on
    the Tomcat server to find configured Connectors:
  
      $ grep “Connector” $CATALINA_HOME/conf/server.xml
  
      Review results and verify all connectors and their associated network ports
    are approved in the SSP.
  
      If connectors are found but are not approved in the SSP, this is a finding.
    '
    desc  'fix', '
      Obtain ISSO approvals for the configured connectors and document in the SSP.
  
      Alternatively, edit the $CATALINA_HOME/conf/server.xml file, remove any
    unapproved connectors, and restart Tomcat by running the command:
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000141-AS-000095'
    tag gid: 'TCAT-AS-000500'
    tag rid: 'TCAT-AS-000500_rule'
    tag stig_id: 'TCAT-AS-000500'
    tag fix_id: 'F-TCAT-AS-000500_fix'
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']

    describe "This is a manual check" do
        skip "Verify all connectors and their associated ports in the $CATALINA_HOME/conf/server.xml are approved in the SSP."
    end
  
end