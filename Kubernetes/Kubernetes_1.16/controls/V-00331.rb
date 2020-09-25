# encoding: UTF-8

control 'V-00331' do
    title 'The application must use FIPS-validated SHA-1 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, and hash-only applications.'
    desc  "Without cryptographic integrity protections, information can be altered by unauthorized users without detection.
	Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the Internet) or an internal network. 
	To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.
	Applications also include HMAC, KDFs, Random Bit Generation, and hash-only applications (e.g., hashing passwords and using SHA-2 to compute a checksum). SHA-2 is not approved for use with digital signatures except with NIST approval for legacy applications. 
	Separate requirements for configuring applications and protocols used by each product (e.g., SNMPv3, SSH, NTP, and other protocols and applications that require server/client authentication) are required to implement this requirement."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000600'
    tag gid: 'V-00331'
    tag rid: ''
    tag stig_id: 'SRG-APP-000600'
    tag fix_id: ''
    tag cci: ['CCI-001967']
    tag nist: ['IA-3 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: This requirement has to do with device authentication. Kubernetes is not responsible for device authentication, thus this requirement is out of scope.'
    end
end