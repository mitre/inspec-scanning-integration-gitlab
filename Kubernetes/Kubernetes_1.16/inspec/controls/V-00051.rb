# encoding: UTF-8

control 'V-00051' do
    title 'The application must initiate session auditing upon startup.'
    desc  "If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i audit-policy-file * 
	If the audit-policy-file is not set, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server manifest and set --audit-policy-file to the audit policy file.
	NOTE: If the API server is running as a Pod, then the manifest will also need updated to mount the host system filesystem where the audit policy file resides."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000092'
    tag gid: 'V-00051'
    tag rid: ''
    tag stig_id: 'SRG-APP-000092'
    tag fix_id: ''
    tag cci: ['CCI-001464']
    tag nist: ['AU-14 (1)']

    describe file('/etc/kubernetes/manifests/kube-apiserver.manifest') do
        its('content') { should match '--audit-policy-file' }
    end
end