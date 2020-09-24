# encoding: UTF-8

control 'V-00152' do
    title 'The application must never automatically remove or disable emergency accounts'
    desc  "Emergency accounts are administrator accounts which are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.
	Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency account is normally a different account which is created for use by vendors or system maintainers.
	To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000234'
    tag gid: 'V-00152'
    tag rid: ''
    tag stig_id: 'SRG-APP-000234'
    tag fix_id: ''
    tag cci: ['CCI-001682']
    tag nist: ['AC-2 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes is designed to deliver mobility. Prevention of mobile code falls outside of Kubernetes.'
    end
end