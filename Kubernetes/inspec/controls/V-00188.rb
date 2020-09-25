# encoding: UTF-8

control 'V-00188' do
    title 'The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
    desc  "Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 
	Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users."
    desc  'rationale', ''
    desc  'check', "The Kubernetes uses the API Server to control communication to the other services that makeup Kubernetes.  The API Server can use several different authorization modes to determine what a user may do within the cluster.  The default authorization mode is is AlwaysAllow, which does no authorization checks and would allow all users to install any software.  To control access to those users and roles responsible for patching and updating the Kubernetes cluster, the API server must have one of the following options set for the authorization mode:
    --authorization-mode=ABAC Attribute-Based Access Control (ABAC) mode allows you to configure policies using local files.
    --authorization-mode=RBAC Role-based access control (RBAC) mode allows you to create and store policies using the Kubernetes API.
    --authorization-mode=Webhook WebHook is an HTTP callback mode that allows you to manage authorization using a remote REST endpoint.
    --authorization-mode=Node Node authorization is a special-purpose authorization mode that specifically authorizes API requests made by kubelets.
    --authorization-mode=AlwaysDeny This flag blocks all requests. Use this flag only for testing."
    desc  'fix', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i authorization-mode * 
	If the setting authorization-mode is set to AlwaysAllow in the Kubernetes API Server manifest file, this is a finding."
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000340'
    tag gid: 'V-00188'
    tag rid: ''
    tag stig_id: 'SRG-APP-000340'
    tag fix_id: ''
    tag cci: ['CCI-002235']
    tag nist: ['AC-6 (10)']

    describe file('/etc/kubernetes/manifests/kube-apiserver.manifest') do
        its('content') { should_not match '--authorization-mode=AlwaysAllow' }
    end
end