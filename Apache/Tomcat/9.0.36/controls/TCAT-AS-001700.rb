# encoding: UTF-8

control 'TCAT-AS-001700' do
    title 'Tomcat users in a management role must be approved by the ISSO.'
    desc  'Deploying applications to Tomcat requires a Tomcat user account that
    is in the \'manager-script\' role. Any user accounts in a Tomcat management
    role must be approved by the ISSO.'
    desc  'rationale', ''
    desc  'check', '
      Review the Tomcat servers System Security Plan/server documentation.
  
      Ensure that user accounts and roles with access to Tomcat management
    features such as the \'manager-script\' role are documented and approved by the
    ISSO.
  
      If the ISSO has not approved of documented roles and users who have
    management rights to the Tomcat server, this is a finding.
    '
    desc  'fix', '
      Document the users and the roles that have been defined for use with the
    Tomcat server.
  
      Ensure that all users and roles with access to Tomcat management features
    and capabilities are approved by the ISSO.
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000516-AS-000237'
    tag gid: 'TCAT-AS-001700'
    tag rid: 'TCAT-AS-001700_rule'
    tag stig_id: 'TCAT-AS-001700'
    tag fix_id: 'F-TCAT-AS-001700_fix'
    tag cci: ['CCI-000366']
    tag nist: ['CM-6 b']
    
    describe "This is a manual check" do 
        skip "Review the SSP or server documentation. Ensure all users and roles with access to the Tomcat 
        management features and capabilities are approved by the ISSO."
    end 
    
end