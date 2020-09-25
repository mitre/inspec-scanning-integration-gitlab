# encoding: UTF-8

control 'V-00189' do
    title 'The application must prevent organization-defined software from executing at higher privilege levels than users executing the software.'
    desc  "In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by organizations."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i ValidatingAdmissionWebhook * 
	
    If a line is not returned that includes enable-admission-plugins and ValidatingAdmissionWebhook, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the argument --enable-admission-plugins to include ValidatingAdmissionWebhook.  Each enabled plugin is separated by commas.
	NOTE:  It is best to implement policies first and then enable the webhook, otherwise, a DoS may occur."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000342'
    tag gid: 'V-00189'
    tag rid: ''
    tag stig_id: 'SRG-APP-000342'
    tag fix_id: ''
    tag cci: ['CCI-002233']
    tag nist: ['AC-6 (8)']

    describe file('/etc/kubernetes/manifests/kube-apiserver.manifest') do
        its('content') { should match 'ValidatingAdmissionWebhook' }
    end
end