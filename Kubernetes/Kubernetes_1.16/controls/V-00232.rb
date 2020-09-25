# encoding: UTF-8

control 'V-00232' do
    title 'Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions organization-defined audit events.'
    desc  "If events associated with non-local administrative access or diagnostic sessions are not logged and audited, a major tool for assessing and investigating attacks would not be available.
	This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.
	This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing \"ping,\" \"ls,\" \"ipconfig,\" or the hardware and software implementing the monitoring port of an Ethernet switch)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000409'
    tag gid: 'V-00232'
    tag rid: ''
    tag stig_id: 'SRG-APP-000409'
    tag fix_id: ''
    tag cci: ['CCI-002884']
    tag nist: ['MA-4 (1) (a)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Any requirements for tools used for nonlocal maintenance are outside the scope of the Kerbernetes SRG.  Audit log events fall outside the Kubernetes SRG.'
    end
end