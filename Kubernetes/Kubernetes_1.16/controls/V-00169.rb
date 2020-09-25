# encoding: UTF-8

control 'V-00169' do
    title 'The application must notify system administrators and ISSO when accounts are created.'
    desc  "Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Sending notification of account creation events to the system administrator and ISSO is one method for mitigating this risk.
	To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000291'
    tag gid: 'V-00169'
    tag rid: ''
    tag stig_id: 'SRG-APP-000291'
    tag fix_id: ''
    tag cci: ['CCI-001683']
    tag nist: ['AC-2 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User account management provided outside Kubernetes scope.'
    end
end