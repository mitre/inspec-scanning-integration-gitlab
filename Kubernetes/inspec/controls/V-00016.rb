# encoding: UTF-8

control 'V-00016' do
    title 'The application must automatically audit account removal actions.'
    desc  "When application accounts are removed, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to remove authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account removal actions provides logging that can be used for forensic purposes.
	To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000029'
    tag gid: 'V-00016'
    tag rid: ''
    tag stig_id: 'SRG-APP-000029'
    tag fix_id: ''
    tag cci: ['CCI-001405']
    tag nist: ['AC-2 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User management provided outside Kubernetes scope.'
    end
end