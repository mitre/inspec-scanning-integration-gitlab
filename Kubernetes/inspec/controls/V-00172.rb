# encoding: UTF-8

control 'V-00172' do
    title 'The application must notify system administrators and ISSO for account removal actions.'
    desc  "When application accounts are removed, user accessibility is affected. Accounts are utilized for identifying users or for identifying the application processes themselves. Sending notification of account removal events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.
	To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000294'
    tag gid: 'V-00172'
    tag rid: ''
    tag stig_id: 'SRG-APP-000294'
    tag fix_id: ''
    tag cci: ['CCI-001686']
    tag nist: ['AC-2 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User account management provided outside Kubernetes scope.'
    end
end