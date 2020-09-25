# encoding: UTF-8

control 'V-00166' do
    title 'The application must be configured to perform real-time malicious code protection scans of files from external sources at endpoints as the files are downloaded, opened, or executed in accordance with organizational security policy.'
    desc  "Malicious code protection mechanisms include, but are not limited, to, anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 
	Malicious code includes viruses, worms, Trojan horses, and Spyware. It is not enough to simply have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 
	This requirement applies to applications providing malicious code protection."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000278'
    tag gid: 'V-00166'
    tag rid: ''
    tag stig_id: 'SRG-APP-000278'
    tag fix_id: ''
    tag cci: ['CCI-001242']
    tag nist: ['SI-3 c 1']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Malicious code protection scanning is performed outside the Kubernetes scope.'
    end
end