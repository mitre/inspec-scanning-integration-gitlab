# encoding: UTF-8

control 'V-00105' do
    title 'The application must enforce password complexity by requiring that at least one special character be used.'
    desc  "Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
	Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 
	Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000169'
    tag gid: 'V-00105'
    tag rid: ''
    tag stig_id: 'SRG-APP-000169'
    tag fix_id: ''
    tag cci: ['CCI-001619']
    tag nist: ['IA-5 (1) (a)']

    describe 'This check is Not Applicable.' do
        skip 'Kubernetes service account must utilize certificates for authentication.'
    end
end