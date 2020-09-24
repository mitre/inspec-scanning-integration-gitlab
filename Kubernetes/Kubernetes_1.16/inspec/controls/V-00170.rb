# encoding: UTF-8

control 'V-00170' do
    title 'The application must notify system administrators and ISSO when accounts are modified.'
    desc  "When application accounts are modified, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account modification events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.
	To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000292'
    tag gid: 'V-00170'
    tag rid: ''
    tag stig_id: 'SRG-APP-000292'
    tag fix_id: ''
    tag cci: ['CCI-001684']
    tag nist: ['AC-2 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User account management provided outside Kubernetes scope.'
    end
end