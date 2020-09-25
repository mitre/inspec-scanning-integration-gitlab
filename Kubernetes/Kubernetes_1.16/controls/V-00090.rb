# encoding: UTF-8

control 'V-00090' do
    title 'The application must use multifactor authentication for network access to privileged accounts.'
    desc  "Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 
	Multifactor authentication requires using two or more factors to achieve authentication. 
	Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). 
	A privileged account is defined as an information system account with authorizations of a privileged user. 
	Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000149'
    tag gid: 'V-00090'
    tag rid: ''
    tag stig_id: 'SRG-APP-000149'
    tag fix_id: ''
    tag cci: ['CCI-000765']
    tag nist: ['IA-2 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Multi-factor authentication falls outside the scope for the Kubernetes.  Multi-factor authentication would be handled by the OS or web frontend and would be addressed in those STIGs and SRGs.'
    end
end