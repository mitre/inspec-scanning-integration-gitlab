# encoding: UTF-8

control 'V-00132' do
    title 'The application must protect the confidentiality and integrity of transmitted information.'
    desc  "Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 
	This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.
	Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node.  Run the command:
	grep -i client-ca-file *
	If the setting feature client-ca-file is not set in the Kubernetes API server manifest file or contains no value, this is a finding."
    desc  'fix', "Edit the Kubernetes Api Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the value of client-ca-file to path containing Approved Organizational Certificate."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000219'
    tag gid: 'V-00132'
    tag rid: ''
    tag stig_id: 'SRG-APP-000219'
    tag fix_id: ''
    tag cci: ['CCI-001184']
    tag nist: ['SC-23']

    describe bash('cd /etc/kubernetes/manifests/ && sudo grep -i client-ca-file *') do
        its('stdout') { should_not be_empty }
    end
end