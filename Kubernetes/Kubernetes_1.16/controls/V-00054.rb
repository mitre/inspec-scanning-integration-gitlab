# encoding: UTF-8

control 'V-00054' do
    title 'The application must produce audit records containing information to establish what type of events occurred.'
    desc  "Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
	Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.
	Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application."
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
    tag gtitle: 'SRG-APP-000095'
    tag gid: 'V-00054'
    tag rid: ''
    tag stig_id: 'SRG-APP-000095'
    tag fix_id: ''
    tag cci: ['CCI-000130']
    tag nist: ['AU-3']

    describe file('/etc/kubernetes/manifests/audit-policy.yml') do
        its('content') { should match '- level: RequestResponse' }
    end
end