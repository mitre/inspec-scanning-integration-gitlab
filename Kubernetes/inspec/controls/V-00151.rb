# encoding: UTF-8

control 'V-00151' do
    title 'The application must isolate security functions from non-security functions.'
    desc  "An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 
	Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. 
	Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Applications restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/sysconfig/ directory on the Kubernetes Master Node.  Run the command:
	more kubelet  
    --protect-kernel-defaults
	If the setting protect-kernel-defaults is set to false or not set in the Kubernetes Kubelet, this is a finding."
    desc  'fix', "Edit the Kubernetes Kuberlet file in the /etc/sysconfig directory on the Kubernetes Master Node.  Set the argument --protect-kernel-defaults to true.  
    Reset Kubelet service using the following command:
	service kubelet restart"
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000233'
    tag gid: 'V-00151'
    tag rid: ''
    tag stig_id: 'SRG-APP-000233'
    tag fix_id: ''
    tag cci: ['CCI-001084']
    tag nist: ['SC-3']

    describe file('/etc/sysconfig/kubelet') do
        its('content') { should match '--protect-kernel-defaults=true' }
    end
end