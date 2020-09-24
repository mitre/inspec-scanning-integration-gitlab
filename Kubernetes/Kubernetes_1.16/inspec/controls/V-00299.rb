# encoding: UTF-8

control 'V-00299' do
    title 'The application must, at a minimum, off-load interconnected systems in real time and off-load standalone systems weekly.'
    desc  "Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
	Off-loading is a common process in information systems with limited audit storage capacity."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000515'
    tag gid: 'V-00299'
    tag rid: ''
    tag stig_id: 'SRG-APP-000515'
    tag fix_id: ''
    tag cci: ['CCI-001851']
    tag nist: ['AU-4 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit records are saved to the hosting system.  Once saved, it is the duty of the hosting system to offload both the host system audit logs along with the Kubernetes audit logs.  This requirement is out of scope.'
    end
end