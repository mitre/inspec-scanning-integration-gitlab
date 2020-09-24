# encoding: UTF-8

control 'V-00333' do
    title 'The application must use FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (non-legacy use).'
    desc  "Without cryptographic integrity protections, information can be altered by unauthorized users without detection.
	To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.
	For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use where needed."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000610'
    tag gid: 'V-00333'
    tag rid: ''
    tag stig_id: 'SRG-APP-000610'
    tag fix_id: ''
    tag cci: ['CCI-000803']
    tag nist: ['IA-7']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes does not authenticate users, but uses external organizational services for authentication and the Kubernetes authorizes users for what the user may do.  This control is about authenticating users before use of cryptographic modules and is out of scope of Kubernetes.'
    end
end