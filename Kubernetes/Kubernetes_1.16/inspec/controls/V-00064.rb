# encoding: UTF-8

control 'V-00064' do
    title 'The application must prevent the execution of prohibited mobile code.'
    desc  "Decisions regarding the employment of mobile code within organizational information systems are based on the potential for the code to cause damage to the system if used maliciously. 
	Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.
	Actions enforced before executing mobile code include, for example, prompting users prior to opening email attachments and disabling automatic execution.
	Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed, downloaded, or executed on all endpoints (e.g., servers, workstations, and smart phones). This requirement applies to applications that execute, evaluate, or otherwise process mobile code (e.g., web applications, browsers, and anti-virus applications)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000112'
    tag gid: 'V-00064'
    tag rid: ''
    tag stig_id: 'SRG-APP-000112'
    tag fix_id: ''
    tag cci: ['CCI-001695']
    tag nist: ['SC-18 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernete control plane is designed to deliver mobility.  Prevention of mobile code falls outside of Kubernetes control plane.'
    end
end