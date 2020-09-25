# encoding: UTF-8

control 'V-00062' do
    title 'The application must alert the IAO and SA (at a minimum) in the event of an audit processing failure.'
    desc  "It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 
	Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.
	This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000108'
    tag gid: 'V-00062'
    tag rid: ''
    tag stig_id: 'SRG-APP-000108'
    tag fix_id: ''
    tag cci: ['CCI-000139']
    tag nist: ['AU-5 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Event notification and monitoring falls outside the Kubernetes scope.'
    end
end