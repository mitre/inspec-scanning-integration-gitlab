# encoding: UTF-8

control 'V-00014' do
    title 'The application must automatically remove or disable temporary user accounts after 72 hours.'
    desc  "If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary user accounts must be set upon account creation. 
	Temporary user accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation. 
	If temporary user accounts are used, the application must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.
	To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000024'
    tag gid: 'V-00014'
    tag rid: ''
    tag stig_id: 'SRG-APP-000024'
    tag fix_id: ''
    tag cci: ['CCI-000016']
    tag nist: ['AC-2 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User management provided outside Kubernetes scope.'
    end
end