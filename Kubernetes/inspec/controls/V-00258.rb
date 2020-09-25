# encoding: UTF-8

control 'V-00258' do
    title 'The application must implement organization-defined security safeguards to protect its memory from unauthorized code execution.'
    desc  "Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.
	Examples of attacks are buffer overflow attacks."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000450'
    tag gid: 'V-00258'
    tag rid: ''
    tag stig_id: 'SRG-APP-000450'
    tag fix_id: ''
    tag cci: ['CCI-002824']
    tag nist: ['SI-16']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Container runtime not in Kubernetes scope and CPU and Memory limits covered in Container Hardening Guidelines.'
    end
end