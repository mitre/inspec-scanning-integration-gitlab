# encoding: UTF-8

control 'V-00164' do
    title 'The application must update malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures.'
    desc  "Malicious code includes viruses, worms, Trojan horses, and spyware. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code. Once this code is installed on endpoints within the network, unauthorized users may be able to breach firewalls and gain access to sensitive data.
	This requirement applies to applications providing malicious code protection. Malicious code protection mechanisms include, but are not limited, to, anti-virus and malware detection software. Malicious code protection mechanisms (including signature definitions and rule sets) must be updated when new releases are available."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000276'
    tag gid: 'V-00164'
    tag rid: ''
    tag stig_id: 'SRG-APP-000276'
    tag fix_id: ''
    tag cci: ['CCI-001240']
    tag nist: ['SI-3 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Malicious code protection mechanism maintenance is performed outside the Kubernetes scope.'
    end
end