# encoding: UTF-8

control 'V-00325' do
    title 'The application that supports citizen- or business-facing applications must prohibit client negotiation to SSL 2.0 or SSL 3.0.'
    desc  "Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.
	This requirement applies to public- or business-facing Transport Layer Security (TLS) gateways (also known as SSL gateways), web servers, and web applications. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance.
	The minimum TLS version required by DoD is 1.2. However, devices and applications may allow client negotiation for systems supporting citizen- and business-facing applications. These devices may be configured to support TLS version 1.1 and 1.0 to enable interaction with citizens and businesses. These devices must not support SSL version 3.0 or earlier."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000565'
    tag gid: 'V-00325'
    tag rid: ''
    tag stig_id: 'SRG-APP-000565'
    tag fix_id: ''
    tag cci: ['CCI-001453']
    tag nist: ['AC-17 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes should not be public facing.  Public facing application are managed outside the Kubernetes Scope.'
    end
end