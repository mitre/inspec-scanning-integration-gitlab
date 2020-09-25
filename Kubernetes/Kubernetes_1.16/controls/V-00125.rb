# encoding: UTF-8

control 'V-00125' do
    title 'The application must prevent the download of prohibited mobile code.'
    desc  "Decisions regarding the employment of mobile code within organizational information systems are based on the potential for the code to cause damage to the system if used maliciously. 
	Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.
	Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed, downloaded, or executed on all endpoints (e.g., servers, workstations, and smart phones). This requirement applies to applications that execute, evaluate, or otherwise process mobile code (e.g., web applications, browsers, and anti-virus applications)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000209'
    tag gid: 'V-00125'
    tag rid: ''
    tag stig_id: 'SRG-APP-000209'
    tag fix_id: ''
    tag cci: ['CCI-001169']
    tag nist: ['SC-18 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes is designed to deliver mobility. Prevention of mobile code falls outside of Kubernetes.'
    end
end