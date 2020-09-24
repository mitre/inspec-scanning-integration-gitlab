# encoding: UTF-8

control 'V-00236' do
    title 'The vulnerability scanning application must implement privileged access authorization to all information systems and infrastructure components for selected organization-defined vulnerability scanning activities.'
    desc  "In certain situations, the nature of the vulnerability scanning may be more intrusive, or the information system component that is the subject of the scanning may contain highly sensitive information. Privileged access authorization to selected system components facilitates more thorough vulnerability scanning and also protects the sensitive nature of such scanning.
	The vulnerability scanning application must utilize privileged access authorization for the scanning account."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000414'
    tag gid: 'V-00236'
    tag rid: ''
    tag stig_id: 'SRG-APP-000414'
    tag fix_id: ''
    tag cci: ['CCI-001067']
    tag nist: ['RA-5 (5)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: The capabilities of a vulnerability scanning tool is outside the Kubernetes scope.'
    end
end