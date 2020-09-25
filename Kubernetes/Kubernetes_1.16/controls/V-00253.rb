# encoding: UTF-8

control 'V-00253' do
    title 'The application must protect the confidentiality and integrity of transmitted information.'
    desc  "Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 
	This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.
	Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node.  Run the command:
	grep -i --kubelet-client-certificate *
    grep -I --kubelet-client-key * 
	If the setting feature--kubelet-client-certificate is not set in the Kubernetes API server manifest file or contains no value, this is a finding.
    If the setting feature--kubelet-client-key is not set in the Kubernetes API server manifest file or contains no value, this is a finding.
    "
    desc  'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the value of --kubelet-client-certificate to path containing Approved Organizational Certificate. Set the value of --Kubelet-client-certificate and --kubelet-client-key Approved Organizational Certificate and Key pair."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000439'
    tag gid: 'V-00253'
    tag rid: ''
    tag stig_id: 'SRG-APP-000439'
    tag fix_id: ''
    tag cci: ['CCI-002418']
    tag nist: ['SC-8']

    
    describe bash('grep -i kubelet-client-certificate /etc/kubernetes/manifests/kube-apiserver.manifest | grep pem') do
        its('stdout') { should_not be_empty }
    end

    describe bash('grep -i kubelet-client-key /etc/kubernetes/manifests/kube-apiserver.manifest | grep pem') do
        its('stdout') { should_not be_empty }
    end
end