# encoding: UTF-8

control 'V-00245' do
    title 'The application must only allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions.'
    desc  "Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.
	The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates. 
	This requirement focuses on communications protection for the application session rather than for the network packet.
	This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000427'
    tag gid: 'V-00245'
    tag rid: ''
    tag stig_id: 'SRG-APP-000427'
    tag fix_id: ''
    tag cci: ['CCI-002470']
    tag nist: ['SC-23 (5)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Baston host handle DOD PKI certificate verification, falls outside the Kubernetes scope.'
    end
end