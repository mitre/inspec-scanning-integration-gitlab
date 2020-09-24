# encoding: UTF-8

control 'V-00184' do
    title 'The application must notify system administrator and ISSO of account enabling actions.'
    desc  "Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Sending notification of account enabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.
	In order to detect and respond to events that affect user accessibility and application processing, applications must notify the appropriate individuals so they can investigate the event.
	To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000320'
    tag gid: 'V-00184'
    tag rid: ''
    tag stig_id: 'SRG-APP-000320'
    tag fix_id: ''
    tag cci: ['CCI-002132']
    tag nist: ['AC-2 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User account management provided outside Kubernetes scope.'
    end
end