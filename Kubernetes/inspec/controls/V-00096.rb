# encoding: UTF-8

control 'V-00096' do
    title 'The application must use FIPS-validated SHA-1 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts.'
    desc  "A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.
	Anti-replay is a cryptographically based mechanism; thus, it must use FIPS-approved algorithms. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Note that the anti-replay service is implicit when data contains monotonically increasing sequence numbers and data integrity is assured. Use of DoD PKI is inherently compliant with this requirement for user and device access. Use of Transport Layer Security (TLS), including application protocols, such as HTTPS and DNSSEC, that use TLS/SSL as the underlying security protocol is also complaint.
	Configure the information system to use the hash message authentication code (HMAC) algorithm for authentication services to Kerberos, SSH, web management tool, and any other access method."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000156'
    tag gid: 'V-00096'
    tag rid: ''
    tag stig_id: 'SRG-APP-000156'
    tag fix_id: ''
    tag cci: ['CCI-001941']
    tag nist: ['IA-2 (8)']

    describe 'This check is Not Applicable.' do
        skip 'Network management is outside the Kubernetes STIG scope.'
    end
end