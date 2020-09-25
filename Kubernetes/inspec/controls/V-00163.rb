# encoding: UTF-8

control 'V-00163' do
    title 'The application must notify IAO and IAM of failed security verification tests.'
    desc  "If personnel are not notified of failed security verification tests, they will not be able to take corrective action and the unsecure condition(s) will remain. 
	Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.
	Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.
	This requirement applies to applications performing security functions and the applications performing security function verification/testing."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000275'
    tag gid: 'V-00163'
    tag rid: ''
    tag stig_id: 'SRG-APP-000275'
    tag fix_id: ''
    tag cci: ['CCI-001294']
    tag nist: ['SI-6 c']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Detection and alerting malicious code notification services is performed outside the Kubernetes scope.'
    end
end