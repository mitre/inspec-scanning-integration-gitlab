# encoding: UTF-8

control 'V-00191' do
    title 'The application must audit the execution of privileged functions.'
    desc  "Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse, and identify the risk from insider threats and the advanced persistent threat."
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
    tag gtitle: 'SRG-APP-000343'
    tag gid: 'V-00191'
    tag rid: ''
    tag stig_id: 'SRG-APP-000343'
    tag fix_id: ''
    tag cci: ['CCI-002234']
    tag nist: ['AC-6 (9)']

    describe file('/etc/kubernetes/manifests/audit-policy.yml') do
        its('content') { should match '- level: RequestResponse' }
    end
end