# encoding: UTF-8

control 'V-00264' do
    title 'The intrusion detection application must detect network services that have not been authorized or approved by the organization-defined authorization or approval processes.'
    desc  "Unauthorized or unapproved network services lack organizational verification or validation and therefore, may be unreliable or serve as malicious rogues for valid services. 
	This requirement can be addressed by a host-based IDS capability or by remote scanning functionality."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000463'
    tag gid: 'V-00264'
    tag rid: ''
    tag stig_id: 'SRG-APP-000463'
    tag fix_id: ''
    tag cci: ['CCI-002683']
    tag nist: ['SI-4 (22)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Intrusion detection is provided outside the Kubernetes scope.'
    end
end