# encoding: UTF-8

control 'V-00082' do
    title 'The application must be configured to disable non-essential capabilities.'
    desc  "It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.
	Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
	Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node.  Run the command:
	grep -i profiling * 
	If the setting profiling is not set in the Kubernetes Controller Manager manifest file or it is set to True, this is a finding."
    desc  'fix', "Edit the Kubernetes Controller Manager manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the argument --profiling  value to false.  
"
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000141'
    tag gid: 'V-00082'
    tag rid: ''
    tag stig_id: 'SRG-APP-000141'
    tag fix_id: ''
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']

    describe file('/etc/kubernetes/manifests/kube-controller-manager.manifest') do
        its('content') { should match '--profiling=false' }
    end
end