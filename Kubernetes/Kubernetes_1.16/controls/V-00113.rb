# encoding: UTF-8

control 'V-00113' do
    title 'The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.'
    desc  "If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.
	The cornerstone of the PKI is the private key used to encrypt or digitally sign information. 
	If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. 
	Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000176'
    tag gid: 'V-00113'
    tag rid: ''
    tag stig_id: 'SRG-APP-000176'
    tag fix_id: ''
    tag cci: ['CCI-000186']
    tag nist: ['IA-5 (2) (b)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User authentication is performed by an external application defined by the organization.  Once authenticated, Kubernetes uses the authenticated user information to implement authorization to services.  Therefore, this requirement does not apply.'
    end
end