# encoding: UTF-8

control 'V-00040' do
    title 'The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.'
    desc  "A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all application information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data. 
	Application specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).
	Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000039'
    tag gid: 'V-00040'
    tag rid: ''
    tag stig_id: 'SRG-APP-000039'
    tag fix_id: ''
    tag cci: ['CCI-001414']
    tag nist: ['AC-4']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes does not communicate out to other systems.  This is more a requirement for services that can be run within kubernetes and those services would have to implement this requirement.'
    end
end