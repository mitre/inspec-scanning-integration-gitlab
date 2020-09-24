# encoding: UTF-8

control 'V-00211' do
    title 'The application must prohibit user installation of software without explicit privileged status.'
    desc  "Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.
	Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. 
	The application must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization. 
	This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i authorization-mode * 
	If the setting authorization-mode is set to AlwaysAllow in the Kubernetes API Server manifest file, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the argument --authorization-mode to any valid authorization mode other than AlwaysAllow."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000378'
    tag gid: 'V-00211'
    tag rid: ''
    tag stig_id: 'SRG-APP-000378'
    tag fix_id: ''
    tag cci: ['CCI-001812']
    tag nist: ['CM-11 (2)']

    describe file('/etc/kubernetes/manifests/kube-apiserver.manifest') do
        its('content') { should_not match '--authorization-mode=AlwaysAllow' }
    end
end