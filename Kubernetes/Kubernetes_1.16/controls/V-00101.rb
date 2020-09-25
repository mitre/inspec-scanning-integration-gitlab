# encoding: UTF-8

control 'V-00101' do
    title 'The application must prohibit password reuse for a minimum of five generations.'
    desc  "Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
	To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 
	If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000165'
    tag gid: 'V-00101'
    tag rid: ''
    tag stig_id: 'SRG-APP-000165'
    tag fix_id: ''
    tag cci: ['CCI-000200']
    tag nist: ['IA-5 (1) (e)']

    describe 'This check is Not Applicable.' do
        skip 'Kubernetes service account must utilize certificates for authentication.'
    end
end