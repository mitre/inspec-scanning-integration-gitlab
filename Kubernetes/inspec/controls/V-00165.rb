# encoding: UTF-8

control 'V-00165' do
    title 'The application must configure malicious code protection mechanisms to perform periodic scans of the information system every seven (7) days.'
    desc  "Malicious code protection mechanisms include, but are not limited, to anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 
	Malicious code includes viruses, worms, Trojan horses, and Spyware. It is not enough to simply have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 
	This requirement applies to applications providing malicious code protection."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000277'
    tag gid: 'V-00165'
    tag rid: ''
    tag stig_id: 'SRG-APP-000277'
    tag fix_id: ''
    tag cci: ['CCI-001241']
    tag nist: ['SI-3 c 1']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Malicious code protection scanning is performed outside the Kubernetes scope.'
    end
end