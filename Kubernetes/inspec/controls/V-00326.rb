# encoding: UTF-8

control 'V-00326' do
    title 'Before establishing a network connection with a Network Time Protocol (NTP) server, the application must authenticate using a bidirectional, cryptographically based authentication method that uses a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the NTP server.'
    desc  "Without device-to-device authentication, communications with malicious devices may be established. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.
	Currently, DoD requires the use of AES for bidirectional authentication since it is the only FIPS-validated AES cipher block algorithm. The NTP uses MD5 authentication keys. The MD5 algorithm is not approved for use in either the FIPS or NIST recommendation; thus, a CAT 1 finding is allocated in CCI-000803. However, the use of MD5 is preferred to no authentication at all and can be used to mitigate this requirement to a CAT II finding.
	The trusted-key statement permits authenticating NTP servers. The product must be configured to support separate keys for each NTP server. Severs should have PKI device certificate involved for use in the device authentication process.
	Server authentication is performed by the client using the server�s public key certificate, which the server presents during the handshake. The exact nature of the cryptographic operation for server authentication is dependent on the negotiated cipher suite and extensions. In most cases (e.g., RSA for key transport, DH and ECDH), authentication is performed explicitly through verification of digital signatures present in certificates and implicitly by the use of the server public key by the client during the establishment of the master secret. A successful \"Finished\" message implies that both parties calculated the same master secret and thus, the server must have known the private key corresponding to the public key used for key establishment."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000570'
    tag gid: 'V-00326'
    tag rid: ''
    tag stig_id: 'SRG-APP-000570'
    tag fix_id: ''
    tag cci: ['CCI-001967']
    tag nist: ['IA-3 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: NTP configuration provided outside Kubernetes Scope.  This is maintained by the Cloud Provider.'
    end
end