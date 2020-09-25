# encoding: UTF-8

control 'V-00319' do
    title 'The application must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
    desc  "Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 
	Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node.  Run the command:
	grep -i audit-log-maxbackup * 
	If the setting audit-log-maxbackup is not set in the Kubernetes API Server manifest file or it is set less than 10, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the value of --audit-log-maxbackup to a minimum of 10."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000516'
    tag gid: 'V-00319'
    tag rid: ''
    tag stig_id: 'SRG-APP-000516'
    tag fix_id: ''
    tag cci: ['CCI-000366']
    tag nist: ['CM-6 b']

    GrepAuditLogMaxBackup = command("cd /etc/kubernetes/manifests/ && sudo grep -i audit-log-maxbackup *").stdout
    
    describe 'This test can only be performed by manual examination.' do
        skip "Manual Check: If the setting audit-log-maxbackup is not set in the Kubernetes API Server manifest file or it is set less than 10, this is a finding. Audit Log Max Backup in Kubernetes Manifests:\n #{GrepAuditLogMaxBackup}"
    end
end