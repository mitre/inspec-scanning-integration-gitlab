# encoding: UTF-8

control 'V-00126' do
    title 'The application must prevent the automatic execution of mobile code in, at a minimum, office applications, browsers, email clients, and mobile code runtime environments, and mobile agent systems.'
    desc  "Mobile code can cause damage to the system. It can execute without explicit action from, or notification to, a user. 
	Preventing automatic execution of mobile code includes, for example, disabling auto execute features on information system components.
	This requirement applies to mobile code-enabled software, which is capable of executing one or more types of mobile code."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000210'
    tag gid: 'V-00126'
    tag rid: ''
    tag stig_id: 'SRG-APP-000210'
    tag fix_id: ''
    tag cci: ['CCI-001170']
    tag nist: ['SC-18 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes is designed to deliver mobility. Prevention of mobile code falls outside of Kubernetes.'
    end
end