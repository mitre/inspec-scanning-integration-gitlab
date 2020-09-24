# encoding: UTF-8

control 'V-00124' do
    title 'The application must block, quarantine, and/or alert administrators when prohibited mobile code is identified.'
    desc  "Decisions regarding the employment of mobile code within organizational information systems are based on the potential for the code to cause damage to the system if used maliciously. 
	Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.
	DoD has defined the corrective actions to be taken, when prohibited mobile code is identified, in DoDI 8552.01, \"Use of Mobile Code Technologies in DoD Information Systems\".
	DoD has identified prohibited mobile code in DoDI 8552.01 as: all Category 1X mobile code, unsigned Category 1A mobile code, Category 2 mobile code that violates usage requirements, all Emerging Technologies mobile code (all mobile code technologies, systems, platforms, or languages whose capabilities and threat level have not yet undergone a risk assessment and been assigned to a risk category), and all mobile code that downloads via an email body or email attachment that executes automatically when the user opens the email body or attachment.
	Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed, downloaded, or executed on all endpoints (e.g., servers, workstations, and smart phones). This requirement applies to applications that execute, evaluate, or otherwise process mobile code (e.g., web applications, browsers, and anti-virus applications). 
	Corrective actions when unacceptable mobile code is detected include, for example, blocking, quarantine, or alerting administrators. Blocking includes, for example, preventing transmission of word processing files with embedded macros when such macros have been defined to be unacceptable mobile code."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000207'
    tag gid: 'V-00124'
    tag rid: ''
    tag stig_id: 'SRG-APP-000207'
    tag fix_id: ''
    tag cci: ['CCI-001662']
    tag nist: ['SC-18 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes is designed to deliver mobility. Prevention of mobile code falls outside of Kubernetes.'
    end
end