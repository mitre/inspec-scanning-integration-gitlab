# encoding: UTF-8

control 'V-00102' do
    title 'The application must enforce password complexity by requiring that at least one uppercase character be used.'
    desc  "Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
	Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000166'
    tag gid: 'V-00102'
    tag rid: ''
    tag stig_id: 'SRG-APP-000166'
    tag fix_id: ''
    tag cci: ['CCI-000192']
    tag nist: ['IA-5 (1) (a)']

    describe 'This check is Not Applicable.' do
        skip 'Kubernetes service account must utilize certificates for authentication.'
    end
end