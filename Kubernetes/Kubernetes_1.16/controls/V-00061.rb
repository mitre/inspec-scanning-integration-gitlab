# encoding: UTF-8

control 'V-00061' do
    title 'The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.'
    desc  "Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 
	Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 
	In addition, the application must have the capability to include organization-defined additional, more detailed information in the audit records for audit events. "
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i audit-policy-file * 
	The file given is the policy file and defines what is audited and what information is included with each event.
	The policy file must look like this:
	# Log all requests at the RequestResponse level.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
	
If the audit policy file does not look like above, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server audit policy and set it to look like below.
	# Log all requests at the RequestResponse level.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
	"
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000101'
    tag gid: 'V-00061'
    tag rid: ''
    tag stig_id: 'SRG-APP-000101'
    tag fix_id: ''
    tag cci: ['CCI-000135']
    tag nist: ['AU-3 (1)']

    describe file('/etc/kubernetes/manifests/audit-policy.yml') do
        its('content') { should match '- level: RequestResponse' }
    end
end