# encoding: UTF-8

control 'V-00215' do
    title 'The application must audit the enforcement actions used to restrict access associated with changes to the application.'
    desc  "Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions. 
	Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact."
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
    tag gtitle: 'SRG-APP-000381'
    tag gid: 'V-00215'
    tag rid: ''
    tag stig_id: 'SRG-APP-000381'
    tag fix_id: ''
    tag cci: ['CCI-001814']
    tag nist: ['CM-5 (1)']

    describe file('/etc/kubernetes/manifests/audit-policy.yml') do
        its('content') { should match 'apiVersion: audit.k8s.io/v1 kind: Policy rules: - level: RequestResponse' }
    end
end