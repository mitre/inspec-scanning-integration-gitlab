# encoding: UTF-8

control 'V-00093' do
    title 'The application must use multifactor authentication for local access to non-privileged accounts.'
    desc  "To assure accountability, prevent unauthenticated access, and prevent misuse of the system, non-privileged users must utilize multi-factor authentication for local access. 
	Multifactor authentication is defined as: using two or more factors to achieve authentication. 
	Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 
	A non-privileged account is defined as an information system account with authorizations of a regular or non-privileged user. 
	Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network. 
	Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000152'
    tag gid: 'V-00093'
    tag rid: ''
    tag stig_id: 'SRG-APP-000152'
    tag fix_id: ''
    tag cci: ['CCI-000768']
    tag nist: ['IA-2 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Multi-factor authentication falls outside the scope for the Kubernetes.  Multi-factor authentication would be handled by the OS or web frontend and would be addressed in those STIGs and SRGs.  Local (physical) access falls outside the container platform scope.'
    end
end