# encoding: UTF-8

control 'V-00108' do
    title 'For accounts using password authentication, the network element must use FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process.'
    desc  "Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.
	The information system must specify the hash algorithm used for authenticating passwords. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption.
	This requirement applies to all accounts, including authentication server; Authorization, Authentication, and Accounting (AAA); and local accounts such as the root account and the account of last resort.
	This requirement only applies to components where this is specific to the function of the device (e.g., TLS VPN or ALG). This does not apply to authentication for the purpose of configuring the device itself (management)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000172'
    tag gid: 'V-00108'
    tag rid: ''
    tag stig_id: 'SRG-APP-000172'
    tag fix_id: ''
    tag cci: ['CCI-000197']
    tag nist: ['IA-5 (1) (c)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes does not authenticate users.  User authentication is performed by external organizational processes.  Kubernetes then uses the authenticated user to determine authorization.'
    end
end