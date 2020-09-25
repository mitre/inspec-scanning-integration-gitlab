# encoding: UTF-8

control 'V-102595' do
  title 'Tomcat users in a management role must be approved by the ISSO.'
  desc  "Deploying applications to Tomcat requires a Tomcat user account that
is in the \"manager-script\" role. Any user accounts in a Tomcat management
role must be approved by the ISSO."
  desc  'rationale', ''
  desc  'check', "
    Review the Tomcat servers System Security Plan/server documentation.

    Ensure that user accounts and roles with access to Tomcat management
features such as the \"manager-script\" role are documented and approved by the
ISSO.

    If the ISSO has not approved of documented roles and users who have
management rights to the Tomcat server, this is a finding.
  "
  desc  'fix', "
    Document the users and the roles that have been defined for use with the
Tomcat server.

    Ensure that all users and roles with access to Tomcat management features
and capabilities are approved by the ISSO.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-102595'
  tag rid: 'SV-111535r1_rule'
  tag stig_id: 'TCAT-AS-001700'
  tag fix_id: 'F-108127r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe "Ensure that user accounts and roles with access to Tomcat management
  features are documented and approved by the ISSO" do 
    skip "If the ISSO has not approved of documented roles and users who have
    management rights to the Tomcat server, this is a finding"
  end 

end