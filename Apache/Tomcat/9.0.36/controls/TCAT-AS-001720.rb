# encoding: UTF-8

control 'TCAT-AS-001720' do
    title 'Connectors must be approved by the ISSO.'
    desc  'Connectors are how Tomcat receives requests over a network port,
    passes them to hosted web applications via HTTP or AJP and then sends back the
    results to the requestor. A port and a protocol are tied to each connector.
    Only connectors approved by the ISSO must be installed. ISSO review will
    consist of validating connector protocol as being secure and required in order
    for the hosted application to operate. The ISSO will ensure that unnecessary or
    insecure connector protocols are not enabled. The ISSO will provide documented
    approval for each connector that will be maintained in the System Security Plan
    (SSP).'
    desc  'rationale', ''
    desc  'check', '
      Review the Tomcat servers System Security Plan/server documentation.
  
      Access the Tomcat server and review the server.xml file.
  
      grep -i \'connector port\' $CATALINA_HOME/conf/server.xml
  
      Compare the active Connectors and their associated IP ports with the
    Connectors documented and approved in the SSP.
  
      If the Connectors that are configured on the Tomcat server are not approved
    by the ISSO and documented in the SSP, this is a finding.
    '
    desc  'fix', '
      Document and obtain ISSO approval for the Connectors that are configured on
    the Tomcat server.
  
      Retain the information in the SSP and present to the auditor in the event
    of a CCRI.
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000516-AS-000237'
    tag gid: 'TCAT-AS-001720'
    tag rid: 'TCAT-AS-001720_rule'
    tag stig_id: 'TCAT-AS-001720'
    tag fix_id: 'F-TCAT-AS-001720_fix'
    tag cci: ['CCI-000366']
    tag nist: ['CM-6 b']
    
    describe "This is a manual check" do 
        skip "Review active Connectors and their IP ports with the Connectors 
        documented and approved in the SSP."
    end
    
end