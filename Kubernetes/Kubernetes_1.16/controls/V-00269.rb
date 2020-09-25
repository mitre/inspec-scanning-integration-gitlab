# encoding: UTF-8

control 'V-00269' do
    title 'The application performing organization-defined security functions must verify correct operation of security functions.'
    desc  "Without verification, security functions may not operate correctly and this failure may go unnoticed. 
	Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy "
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000472'
    tag gid: 'V-00269'
    tag rid: ''
    tag stig_id: 'SRG-APP-000472'
    tag fix_id: ''
    tag cci: ['CCI-002696']
    tag nist: ['SI-6 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Defined roles, responsibilities and procedures is the organizations duty to define.  System restarts, shutdown and failures notifications are managed by the OS. The control is outside the Kubernetes scope.'
    end
end