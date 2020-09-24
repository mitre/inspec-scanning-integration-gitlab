# encoding: UTF-8

control 'V-00092' do
    title 'The application must use multifactor authentication for local access to privileged accounts.'
    desc  "To assure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 
	Multifactor authentication is defined as: using two or more factors to achieve authentication. 
	Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 
	A privileged account is defined as an information system account with authorizations of a privileged user. 
	Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network. 
	Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000151'
    tag gid: 'V-00092'
    tag rid: ''
    tag stig_id: 'SRG-APP-000151'
    tag fix_id: ''
    tag cci: ['CCI-000767']
    tag nist: ['IA-2 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Multi-factor authentication falls outside the scope for the Kubernetes.  Multi-factor authentication would be handled by the OS or web frontend and would be addressed in those STIGs and SRGs.  Local (physical) access falls outside the container platform scope.'
    end
end