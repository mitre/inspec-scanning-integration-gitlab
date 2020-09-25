# encoding: UTF-8

control 'V-00268' do
    title 'The intrusion detection application must alert the IAO, IAM, and other individuals designated by the local organization when the following Indicators of Compromise (IOCs) or potential compromise are detected: real time intrusion detection; threats identified by authoritative sources (e.g., CTOs); and Category I, II, IV, and VII incidents in accordance with CJCSM 6510.01B.'
    desc  "When a security event occurs, the application that has detected the event must immediately notify the appropriate support personnel so they can respond appropriately. 
	Alerts may be generated from a variety of sources, including, audit records or inputs from malicious code protection mechanisms, intrusion detection, or prevention mechanisms. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. Individuals designated by the local organization to receive alerts may include, for example, system administrators, mission/business owners, or system owners.
	IOCs are forensic artifacts from intrusions that are identified on organizational information systems (at the host or network level). IOCs provide organizations with valuable information on objects or information systems that have been compromised. These indicators reflect the occurrence of a compromise or a potential compromise.
	This requirement applies to applications that provide monitoring capability for unusual/unauthorized activities including, but are not limited to, host-based intrusion detection, anti-virus, and malware applications."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000471'
    tag gid: 'V-00268'
    tag rid: ''
    tag stig_id: 'SRG-APP-000471'
    tag fix_id: ''
    tag cci: ['CCI-002664']
    tag nist: ['SI-4 (5)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Intrusion detection is provided outside the Kubernetes scope.'
    end
end