# encoding: UTF-8

control 'V-00213' do
    title 'The application must implement organization-defined automated security responses if baseline configurations are changed in an unauthorized manner.'
    desc  "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the system. Changes to information system configurations can have unintended side effects, some of which may be relevant to security. 
	Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the application. Examples of security responses include, but are not limited to the following: halting application processing; halting selected application functions; or issuing alerts/notifications to organizational personnel when there is an unauthorized modification of a configuration item."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000379'
    tag gid: 'V-00213'
    tag rid: ''
    tag stig_id: 'SRG-APP-000379'
    tag fix_id: ''
    tag cci: ['CCI-001744']
    tag nist: ['CM-3 (5)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Unauthorized changes to software would be monitored by the OS or external tools.  Not by Kubernetes itself.'
    end
end