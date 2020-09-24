# encoding: UTF-8

control 'V-00234' do
    title 'The application must configure web management tools with FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
    desc  "Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.
	Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the Internet) or an internal network."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000412'
    tag gid: 'V-00234'
    tag rid: ''
    tag stig_id: 'SRG-APP-000412'
    tag fix_id: ''
    tag cci: ['CCI-003123']
    tag nist: ['MA-4 (6)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Web maintenance tool falls outside the Kubernetes scope.'
    end
end