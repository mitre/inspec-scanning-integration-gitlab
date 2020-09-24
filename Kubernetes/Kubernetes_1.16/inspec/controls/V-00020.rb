# encoding: UTF-8

control 'V-00020' do
    title 'The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
    desc  "The application must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs."
    desc  'rationale', ''
    desc  'check', "To view the available namespaces, run the command:
	kubectl get namespaces
	The default namespaces to be validated are default, kube-public and kube-node-lease if it is created.  
	For the default namespace, execute the commands:
	kubectl config set-context --current --namespace=default
    kubectl get all
	For the kube-public namespace, execute the commands:
	kubectl config set-context --current --namespace=kube-public
    kubectl get all
	For the kube-node-lease namespace, execute the commands:
	kubectl config set-context --current --namespace=kube-node-lease
    kubectl get all
	The only valid return values are the kubernetes service (i.e. service/kubernetes) and nothing at all.
	if a return value is returned from the \"kubectl get all\" command and it is not the kubernetes service (i.e. service/kubernetes), this is a finding."
    desc  'fix', "Move any user-managed resources from the default, kube-public and kube-node-lease namespaces to user namespaces."
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000516'
    tag gid: 'V-00020'
    tag rid: ''
    tag stig_id: 'SRG-APP-000516'
    tag fix_id: ''
    tag cci: ['CCI-000366']
    tag nist: ['CM-6 b']

    kubectlNameSpaces = command("kubectl get namespaces").stdout

    describe 'This test can only be performed by manual examination.' do
        skip "Manual Check: Please check STIG for command reference. List of Name Spaces in Kubernetes Instance:\n #{kubectlNameSpaces}"
    end
end