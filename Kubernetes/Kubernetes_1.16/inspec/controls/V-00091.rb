# encoding: UTF-8

control 'V-00091' do
    title 'The application must use multifactor authentication for network access to non-privileged accounts.'
    desc  "To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 
	Multifactor authentication uses two or more factors to achieve authentication. 
	Factors include:
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric). 
	A non-privileged account is any information system account with authorizations of a non-privileged user. 
	Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.
	Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000150'
    tag gid: 'V-00091'
    tag rid: ''
    tag stig_id: 'SRG-APP-000150'
    tag fix_id: ''
    tag cci: ['CCI-000766']
    tag nist: ['IA-2 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Multi-factor authentication falls outside the scope for the Kubernetes.  Multi-factor authentication would be handled by the OS or web frontend and would be addressed in those STIGs and SRGs.'
    end
end  