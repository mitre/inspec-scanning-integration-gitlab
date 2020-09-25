# encoding: UTF-8

control 'V-00127' do
    title 'The application must separate user functionality (including user interface services) from information system management functionality.'
    desc  "Application management functionality includes functions necessary for administration and requires privileged user access. Allowing non-privileged users to access application management functionality capabilities increases the risk that non-privileged users may obtain elevated privileges. 
	The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, different TCP/UDP ports, virtualization techniques, combinations of these methods, or other methods, as appropriate. 
	An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. This may include isolating the administrative interface on a different security domain and with additional access controls."
    desc  'rationale', ''
    desc  'check', "On the Master node, run the command:
	kubectl get pods --all-namespaces
	Review the namespaces and pods that are returned.  Kubernetes system namespaces kube-node-lease, kube-public and kube-system.
	If any user pods are present in the Kubernetes system namespaces, this is a finding. "
    desc  'fix', "Move an user pods that are present in the Kubernetes system namespaces to user specific namespaces."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000211'
    tag gid: 'V-00127'
    tag rid: ''
    tag stig_id: 'SRG-APP-000211'
    tag fix_id: ''
    tag cci: ['CCI-001082']
    tag nist: ['SC-2']

    describe bash('kubectl get pods --all-namespaces | grep -v \'kube-node-lease\|kube-public\|kube-system\'') do
        its('stdout') { should be_empty }
        its('stderr') { should eq '' }
    end
end