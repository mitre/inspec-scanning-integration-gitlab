# encoding: UTF-8

control 'V-00196' do
    title 'The application must off-load audit records onto a different system or media than the system being audited.'
    desc  "Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
	Off-loading is a common process in information systems with limited audit storage capacity."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000358'
    tag gid: 'V-00196'
    tag rid: ''
    tag stig_id: 'SRG-APP-000358'
    tag fix_id: ''
    tag cci: ['CCI-001851']
    tag nist: ['AU-4 (1)']
    
    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: The audit logs are stored on the hosting operating system and would be configured by the OS.'
    end
end