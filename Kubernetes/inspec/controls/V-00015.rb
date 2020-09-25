# encoding: UTF-8

control 'V-00015' do
    title 'The application must automatically disable accounts after a 35 day period of account inactivity.'
    desc  "Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Applications need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise. 
	To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 
	This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are local login administrator accounts used by system administrators when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000025'
    tag gid: 'V-00015'
    tag rid: ''
    tag stig_id: 'SRG-APP-000025'
    tag fix_id: ''
    tag cci: ['CCI-000017']
    tag nist: ['AC-2 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User management provided outside Kubernetes scope.'
    end
end