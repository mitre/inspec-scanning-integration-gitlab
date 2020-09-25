# encoding: UTF-8

control 'V-00270' do
    title 'The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.'
    desc  "Without verification, security functions may not operate correctly and this failure may go unnoticed. 
	Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.
	Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.
	This requirement applies to applications performing security functions and the applications performing security function verification/testing."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000473'
    tag gid: 'V-00270'
    tag rid: ''
    tag stig_id: 'SRG-APP-000473'
    tag fix_id: ''
    tag cci: ['CCI-002699']
    tag nist: ['SI-6 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Defined roles, responsibilities and procedures is the organizations duty to define.  System restarts, shutdown and failures notifications are managed by the OS. The control is outside the Kubernetes scope.'
    end
end