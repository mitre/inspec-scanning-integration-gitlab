# encoding: UTF-8

control 'V-00322' do
    title 'The application must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
    desc  "Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 
	Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements."
    desc  'rationale', ''
    desc  'check', "Review the permissions of the Kubernetes PKI cert files by using the command:
	find /etc/kubernetes/pki -name \"*.crt\" | xargs stat -c '%n %a'
	If any of the files are have permissions more permissive than 644, this is a finding."
    desc  'fix', "Change the ownership of the cert files to 644 by executing the command:
	chmod -R 644 /etc/kubernetes/pki/*.crt "
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000516'
    tag gid: 'V-00322'
    tag rid: ''
    tag stig_id: 'SRG-APP-000516'
    tag fix_id: ''
    tag cci: ['CCI-000366']
    tag nist: ['CM-6 b']

    describe bash('find /etc/kubernetes/pki -name "*.crt" | xargs stat -c \'%n %a\' | awk \'$2>644\'') do
        its('stdout') { should be_empty }
        its('stderr') { should eq '' }
    end
end