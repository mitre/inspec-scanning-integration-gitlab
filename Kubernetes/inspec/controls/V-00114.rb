# encoding: UTF-8

control 'V-00114' do
    title 'The application must map the authenticated identity to the individual user or group account for PKI-based authentication.'
    desc  "Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000177'
    tag gid: 'V-00114'
    tag rid: ''
    tag stig_id: 'SRG-APP-000177'
    tag fix_id: ''
    tag cci: ['CCI-000187']
    tag nist: ['IA-5 (2) (c)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: User authentication is performed by an external application defined by the organization.  Once authenticated, Kubernetes uses the authenticated user information to implement authorization to services.  Therefore, this requirement does not apply.'
    end
end