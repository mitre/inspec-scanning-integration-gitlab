# encoding: UTF-8

control 'V-00045' do
    title 'Applications scanning for malicious code must scan all media used for system maintenance prior to use.'
    desc  "There are security-related issues arising from software brought into the information system specifically for diagnostic and repair actions (e.g., a software packet sniffer installed on a system in order to troubleshoot system traffic, or a vendor installing or running a diagnostic application in order to troubleshoot an issue with a vendor supported system).
	If, upon inspection of media containing maintenance diagnostic and test programs, organizations determine that the media contain malicious code, the incident is handled consistent with organizational incident handling policies and procedures.
	This requirement addresses security-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems. Maintenance tools can include hardware, software, and firmware items. Maintenance tools are potential vehicles for transporting malicious code, either intentionally or unintentionally, into a facility and subsequently into organizational information systems. Maintenance tools can include, for example, hardware/software diagnostic test equipment and hardware/software packet sniffers. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing \"ping,\" \"ls,\" \"ipconfig,\" or the hardware and software implementing the monitoring port of an Ethernet switch)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000073'
    tag gid: 'V-00045'
    tag rid: ''
    tag stig_id: 'SRG-APP-000073'
    tag fix_id: ''
    tag cci: ['CCI-000870']
    tag nist: ['MA-3 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Application scanning is performed outside the Kubernetes scope.'
    end
end