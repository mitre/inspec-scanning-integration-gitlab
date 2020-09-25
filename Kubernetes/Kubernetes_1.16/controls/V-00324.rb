# encoding: UTF-8

control 'V-00324' do
    title 'The application that supports Government-only services must prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0.'
    desc  "Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.
	This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation, either on DoD-only or on public-facing servers."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i tls-min-version * 
	If the setting tls-min-version is not set in the Kubernetes API Server manifest file or it is set to VersionTLS10 or VersionTLS11, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the value of --tls-min-version to either VersionTLS12 or VersionTLS13."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000560'
    tag gid: 'V-00324'
    tag rid: ''
    tag stig_id: 'SRG-APP-000560'
    tag fix_id: ''
    tag cci: ['CCI-001453']
    tag nist: ['AC-17 (2)']

    describe bash('grep -i tls-min-version kube-apiserver.manifest') do
        its('stdout') { should_not be_empty }
        its('stdout') { should_not match 'tls-min-version=VersionTLS10' }
        its('stdout') { should_not match 'tls-min-version=VersionTLS11' }
    end
end