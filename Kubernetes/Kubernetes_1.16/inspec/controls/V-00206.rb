# encoding: UTF-8

control 'V-00206' do
    title 'The application must compare internal information system clocks at least every 24 hours with an authoritative time server.'
    desc  "Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. 
	Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).
	This requirement only applies to applications that specifically provide time comparison and synchronization/update functions (e.g., an NTP client). Applications can utilize a capability of an operating system to meet this requirement."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000371'
    tag gid: 'V-00206'
    tag rid: ''
    tag stig_id: 'SRG-APP-000371'
    tag fix_id: ''
    tag cci: ['CCI-001891']
    tag nist: ['AU-8 (1) (a)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Internal information system clock sync performed by cloud provider and is outside the Kubernetes scope.'
    end
end