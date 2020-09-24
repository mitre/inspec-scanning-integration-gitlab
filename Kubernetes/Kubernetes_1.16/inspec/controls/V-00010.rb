# encoding: UTF-8

control 'V-00010' do
    title 'The application must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
    desc  "Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.
	This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications and is not applicable to virtual private network (VPN) devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation on either DoD-only or on public-facing servers."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -I  peer-auto-tls * 
	If the setting peer-auto-tls is not set in the Kubernetes etcd manifest file or it is set to true, this is a finding."
    desc  'fix', "Edit the Kubernetes etcd manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the value of  peer-auto-tls to false."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000014'
    tag gid: 'V-00010'
    tag rid: ''
    tag stig_id: 'SRG-APP-000014'
    tag fix_id: ''
    tag cci: ['CCI-000068']
    tag nist: ['AC-17 (2)']

    describe file('/etc/kubernetes/manifests/etcd-main.manifest') do
        its('content') { should match 'peer-auto-tls=false' }
    end
end