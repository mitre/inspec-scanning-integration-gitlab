# encoding: UTF-8

control 'V-00265' do
    title 'The intrusion detection application must, when unauthorized network services are detected, log the event and alert the IAO, IAM, and other individuals designated by the local organization.'
    desc  "Unauthorized or unapproved network services lack organizational verification or validation and therefore, may be unreliable or serve as malicious rogues for valid services. The detection of such unauthorized services must be logged and appropriate personnel must be notified. 
	This requirement can be addressed by a host-based IDS capability or by remote scanning functionality."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000464'
    tag gid: 'V-00265'
    tag rid: ''
    tag stig_id: 'SRG-APP-000464'
    tag fix_id: ''
    tag cci: ['CCI-002684']
    tag nist: ['SI-4 (22)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Intrusion detection is provided outside the Kubernetes scope.'
    end
end