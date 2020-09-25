# encoding: UTF-8

control 'V-00303' do
    title 'The application must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
    desc  "Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 
	Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements."
    desc  'rationale', ''
    desc  'check', "Check if Kube-Proxy is running and obtain --kubeconfig parameter use the following command:
    ps -ef | grep kube-proxy
	Review the permissions of the Kubernetes Kube Proxy by using the command:
    stat -c %a <location from --kubeconfig>
	If the file has permissions more permissive than 644, this is a finding."
    desc  'fix', "Change the permissions of the Kube Proxy  to 644 by executing the command:
	chown 644 <location from kubeconfig>."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000516'
    tag gid: 'V-00303'
    tag rid: ''
    tag stig_id: 'SRG-APP-000516'
    tag fix_id: ''
    tag cci: ['CCI-000366']
    tag nist: ['CM-6 b']

    describe file('/var/lib/kube-proxy/kubeconfig') do
        it { should_not be_more_permissive_than('0644') }
    end
end