# encoding: UTF-8

control 'V-00110' do
    title 'The application must enforce 24 hours/1 day as the minimum password lifetime.'
    desc  "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.
	Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000173'
    tag gid: 'V-00110'
    tag rid: ''
    tag stig_id: 'SRG-APP-000173'
    tag fix_id: ''
    tag cci: ['CCI-000198']
    tag nist: ['IA-5 (1) (d)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes service account must utilize certificates for authentication.'
    end
end