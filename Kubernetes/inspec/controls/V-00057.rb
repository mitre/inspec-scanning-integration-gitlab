# encoding: UTF-8

control 'V-00057' do
    title 'The application must produce audit records containing information to establish the source of the events.'
    desc  "Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.
	In addition to logging where events occur within the application, the application must also produce audit records that identify the application itself as the source of the event.
	In the case of centralized logging, the source would be the application name accompanied by the host or client name. 
	In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know the source of the event, particularly in the case of centralized logging.
	Associating information about the source of the event within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. "
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
    tag gtitle: 'SRG-APP-000098'
    tag gid: 'V-00057'
    tag rid: ''
    tag stig_id: 'SRG-APP-000098'
    tag fix_id: ''
    tag cci: ['CCI-000133']
    tag nist: ['AU-3']

    describe file('/etc/kubernetes/manifests/audit-policy.yml') do
        its('content') { should match '- level: RequestResponse' }
    end
end