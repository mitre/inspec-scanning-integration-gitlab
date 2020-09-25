# encoding: UTF-8

control 'V-00200' do
    title 'The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
    desc  "If the audit reduction capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack, or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.
	Audit reduction capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools. 
	This requirement is specific to applications with audit reduction capabilities."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000365'
    tag gid: 'V-00200'
    tag rid: ''
    tag stig_id: 'SRG-APP-000365'
    tag fix_id: ''
    tag cci: ['CCI-001877']
    tag nist: ['AU-7 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit capabilities fall oustide the Kubernetes scope.'
    end
end