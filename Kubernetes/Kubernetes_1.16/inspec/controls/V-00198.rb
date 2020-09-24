# encoding: UTF-8

control 'V-00198' do
    title 'The application must provide an immediate real-time alert to the SA and IAO, at a minimum, of all audit failure events requiring real-time alerts.'
    desc  "It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 
	Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000360'
    tag gid: 'V-00198'
    tag rid: ''
    tag stig_id: 'SRG-APP-000360'
    tag fix_id: ''
    tag cci: ['CCI-001858']
    tag nist: ['AU-5 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Auditable event notifications fall outside the Kubernetes scope.'
    end
end