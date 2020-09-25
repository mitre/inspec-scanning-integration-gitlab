# encoding: UTF-8

control 'V-00266' do
    title 'The intrusion detection application must continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions.'
    desc  "Evidence of malicious code is used to identify potentially compromised information systems or information system components. Unusual/unauthorized activities or conditions related to information system inbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. 
	This requirement applies to applications that provide monitoring capability for unusual/unauthorized activities including, but are not limited to, host-based intrusion detection, anti-virus, and malware applications."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000469'
    tag gid: 'V-00266'
    tag rid: ''
    tag stig_id: 'SRG-APP-000469'
    tag fix_id: ''
    tag cci: ['CCI-002661']
    tag nist: ['SI-4 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Intrusion detection is provided outside the Kubernetes scope.'
    end
end