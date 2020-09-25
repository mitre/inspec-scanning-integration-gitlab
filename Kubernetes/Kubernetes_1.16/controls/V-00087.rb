# encoding: UTF-8

control 'V-00087' do
    title 'The application must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
    desc  "Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.
	Application communication sessions are protected utilizing transport encryption protocols, such as TLS. TLS provides web applications with a means to be able to authenticate user sessions and encrypt application traffic. Session authentication can be single (one way) or mutual (two way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other. 
	This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA). 
	This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of TLS mutual authentication (two-way/bidirectional)."
    desc  'rationale', ''
    desc  'check', "On the Master node, run the command:
	kubectl get pods --all-namespaces
	The list returned is all pods running within the Kubernetes cluster.  For those pods running within the user namespaces (System namespaces are kube-system, kube-node-lease and kube-public), run the command:
	kubectl get pod podname -o yaml | grep -i port
	NOTE: In the above command, podname is the name of the pod.  For the command to work correctly, the current context must be changed to the namespace for the pod.  The command to do this is:
	kubectl config set-context --current --namespace=namespace-name
	where namespace-name is the name of the namespace.
	Review the ports that are returned for the pod.
	If any host priviledged ports are returned for any of the pods, this is a finding."
    desc  'fix', "For any of the pods that are using host Privileged ports, reconfigure the pod to use a service to map a host non-privileged port to the pod port or reconfigure the image to use non-privileged ports."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000142'
    tag gid: 'V-00087'
    tag rid: ''
    tag stig_id: 'SRG-APP-000142'
    tag fix_id: ''
    tag cci: ['CCI-000382']
    tag nist: ['CM-7 b']

    kubectlGetPods = command("kubectl get pods --all-namespaces").stdout

    describe 'This test can only be performed by manual examination.' do
        skip "Manual Check: Please check STIG for command reference. List of Pods in Kubernetes Instance:\n #{kubectlGetPods}"
    end
end