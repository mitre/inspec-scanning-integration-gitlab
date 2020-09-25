# encoding: UTF-8

control 'V-00263' do
    title 'The intrusion detection application must be configured to integrate with a system-wide intrusion detection system.'
    desc  "Without coordinated reporting between separate devices, it is not possible to identify the true scale and possible target of an attack. 
	This may be implemented, for example, by means of configuring the individual intrusion detection tool to integrate with a central management console.
	This requirement applies to applications that provide monitoring capability for unusual/unauthorized activities including, but are not limited to, host-based intrusion detection, anti-virus, and malware applications."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000462'
    tag gid: 'V-00263'
    tag rid: ''
    tag stig_id: 'SRG-APP-000462'
    tag fix_id: ''
    tag cci: ['CCI-002656']
    tag nist: ['SI-4 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Intrusion detection is provided outside the Kubernetes scope.'
    end
end