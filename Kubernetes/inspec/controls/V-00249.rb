# encoding: UTF-8

control 'V-00249' do
    title 'The application must protect against or limit the effects of all types of Denial of Service (DoS) attacks by employing organization-defined security safeguards.'
    desc  "DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.
	This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node.  Run the command:
	grep -I request-timeout * 
	If the setting request-timeout is set to 0 in the Kubernetes API Server manifest file, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the value of request-timeout greater than 0 value."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000435'
    tag gid: 'V-00249'
    tag rid: ''
    tag stig_id: 'SRG-APP-000435'
    tag fix_id: ''
    tag cci: ['CCI-002385']
    tag nist: ['SC-5']

    describe file('/etc/kubernetes/manifests/kube-apiserver.manifest') do
        its('content') { should_not match 'request-timeout=0' }
    end
end