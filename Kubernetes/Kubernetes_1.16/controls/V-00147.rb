# encoding: UTF-8

control 'V-00147' do
    title 'The application must generate unique session identifiers using a FIPS-validated Random Number Generator (RNG) based on the Deterministic Random Bit Generators (DRBG) algorithm.'
    desc  "Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.
	Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions. 
	The DRBGs Hash_DRBG, HMAC_DRBG, and CTR_DRBG are recommended for use with RNGs. 
	This requirement is applicable to devices that use a web interface for device management."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000224'
    tag gid: 'V-00147'
    tag rid: ''
    tag stig_id: 'SRG-APP-000224'
    tag fix_id: ''
    tag cci: ['CCI-001188']
    tag nist: ['SC-23 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Network management falls outside the scope of Kubernetes scope.'
    end
end