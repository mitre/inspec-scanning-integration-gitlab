# encoding: UTF-8

control 'V-00225' do
    title 'The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.'
    desc  "Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial login. 
	Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts which allow the users to log in, yet force them to change the password once they have successfully authenticated."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000397'
    tag gid: 'V-00225'
    tag rid: ''
    tag stig_id: 'SRG-APP-000397'
    tag fix_id: ''
    tag cci: ['CCI-002041']
    tag nist: ['IA-5 (1) (f)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Endpoint management falls outside the Kubernetes scope.'
    end
end