# encoding: UTF-8

control 'V-00328' do
    title 'The application must authenticate endpoint devices (servers) before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
    desc  "Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk, such as remote connections.
	This requires device-to-device authentication. Information systems must use IEEE 802.1x, Extensible Authentication Protocol [EAP], Radius server with EAP-Transport Layer Security [TLS] authentication, or Kerberos to identify/authenticate devices on local and/or wide area networks."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000580'
    tag gid: 'V-00328'
    tag rid: ''
    tag stig_id: 'SRG-APP-000580'
    tag fix_id: ''
    tag cci: ['CCI-001967']
    tag nist: ['IA-3 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Endpoint management with servers provided outside Kubernetes scope.'
    end
end