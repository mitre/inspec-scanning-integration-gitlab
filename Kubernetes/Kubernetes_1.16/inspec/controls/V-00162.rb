# encoding: UTF-8

control 'V-00162' do
    title 'The application must automatically update malicious code protection mechanisms.'
    desc  "Malicious software detection applications need to be constantly updated in order to identify new threats as they are discovered. 
	All malicious software detection software must come with an update mechanism that automatically updates the application and any associated signature definitions. The organization (including any contractor to the organization) is required to promptly install security-relevant malicious code protection software updates. Examples of relevant updates include anti-virus signatures, detection heuristic rule sets, and/or file reputation data employed to identify and/or block malicious software from executing.
	Malicious code includes viruses, worms, Trojan horses, and Spyware. 
	This requirement applies to applications providing malicious code protection."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000272'
    tag gid: 'V-00162'
    tag rid: ''
    tag stig_id: 'SRG-APP-000272'
    tag fix_id: ''
    tag cci: ['CCI-001247']
    tag nist: ['SI-3 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Malicious code protection mechanism is performed outside the Kubernetes scope.'
    end
end