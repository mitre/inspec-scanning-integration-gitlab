# encoding: UTF-8

control 'V-00167' do
    title 'The application must be configured to block and quarantine malicious code upon detection, then send an immediate alert to appropriate individuals.'
    desc  "Malicious code protection mechanisms include, but are not limited, to anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 
	Applications providing this capability must be able to perform actions in response to detected malware. Responses include blocking, quarantining, deleting, and alerting. Other technology- or organization-specific responses may also be employed to satisfy this requirement.
	Malicious code includes viruses, worms, Trojan horses, and Spyware. 
	This requirement applies to applications providing malicious code protection."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000279'
    tag gid: 'V-00167'
    tag rid: ''
    tag stig_id: 'SRG-APP-000279'
    tag fix_id: ''
    tag cci: ['CCI-001243']
    tag nist: ['SI-3 c 2']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Malicious code protection is performed outside the Kubernetes scope.'
    end
end