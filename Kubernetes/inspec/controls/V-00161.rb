# encoding: UTF-8

control 'V-00161' do
    title 'Flaw remediation applications must employ automated mechanisms to determine the state of information system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).'
    desc  "Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the system components may remain vulnerable to the exploits presented by undetected software flaws.
	To support this requirement, the flaw remediation application may have automated mechanisms that perform automated scans for security-relevant software updates (e.g., patches, service packs, and hot fixes) and security vulnerabilities of the information system components being monitored. For example, a method of compliance would be an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools as specified in the requirement."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000270'
    tag gid: 'V-00161'
    tag rid: ''
    tag stig_id: 'SRG-APP-000270'
    tag fix_id: ''
    tag cci: ['CCI-001233']
    tag nist: ['SI-2 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Automated mechanisms using HBSS, antivirus and other external scans are outside the Kubernetes scope.'
    end
end