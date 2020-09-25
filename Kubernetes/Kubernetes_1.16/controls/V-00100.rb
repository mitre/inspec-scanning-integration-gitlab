# encoding: UTF-8

control 'V-00100' do
    title 'The application must enforce a minimum 15-character password length.'
    desc  "The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.
	Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 
	Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000164'
    tag gid: 'V-00100'
    tag rid: ''
    tag stig_id: 'SRG-APP-000164'
    tag fix_id: ''
    tag cci: ['CCI-000205']
    tag nist: ['IA-5 (1) (a)']

    describe 'This check is Not Applicable.' do
        skip 'Kubernetes service account must utilize certificates for authentication.'
    end
end