# encoding: UTF-8

control 'V-00278' do
    title 'The application must prompt the user for action prior to executing mobile code.'
    desc  "Mobile code can cause damage to the system. It can execute without explicit action from, or notification to, a user. 
	Actions enforced before executing mobile code include, for example, prompting users prior to opening email attachments and disabling automatic execution.
	This requirement applies to mobile code-enabled software, which is capable of executing one or more types of mobile code."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000488'
    tag gid: 'V-00278'
    tag rid: ''
    tag stig_id: 'SRG-APP-000488'
    tag fix_id: ''
    tag cci: ['CCI-002460']
    tag nist: ['SC-18 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes control plane is designed to deliver mobility. Mobile code falls outside of Kubernetes control plane.'
    end
end