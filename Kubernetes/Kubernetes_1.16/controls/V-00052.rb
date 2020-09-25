# encoding: UTF-8

control 'V-00052' do
    title 'The application must initiate session auditing upon startup.'
    desc  "If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i audit-log-path * 
	If the audit-log-path is not set, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server manifest and set --audit-log-path to a secure location for the audit logs to be written.
	NOTE: If the API server is running as a Pod, then the manifest will also need updated to mount the host system filesystem where the audit log file is to be written."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000092'
    tag gid: 'V-00052'
    tag rid: ''
    tag stig_id: 'SRG-APP-000092'
    tag fix_id: ''
    tag cci: ['CCI-001464']
    tag nist: ['AU-14 (1)']

    describe file('/etc/kubernetes/manifests/kube-apiserver.manifest') do
        its('content') { should match '--audit-log-path' }
    end
end