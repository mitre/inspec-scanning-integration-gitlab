# encoding: UTF-8

control 'V-00280' do
    title 'The application must generate audit records when successful/unsuccessful attempts to access security levels occur.'
    desc  "Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
	Audit records can be generated from various components within the information system (e.g., module or policy filter)."
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
    tag gtitle: 'SRG-APP-000493'
    tag gid: 'V-00280'
    tag rid: ''
    tag stig_id: 'SRG-APP-000493'
    tag fix_id: ''
    tag cci: ['CCI-000172']
    tag nist: ['AU-12 c']

    describe file('/etc/kubernetes/manifests/audit-policy.yml') do
        its('content') { should match 'apiVersion: audit.k8s.io/v1 kind: Policy rules: - level: RequestResponse' }
    end
end