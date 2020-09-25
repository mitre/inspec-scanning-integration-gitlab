# encoding: UTF-8

control 'V-00207' do
    title 'The application must synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.'
    desc  "Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 
	Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.
	This requirement only applies to applications that specifically provide time comparison and synchronization/update functions (e.g., an NTP client). Applications can utilize the capability of an operating system to meet this requirement."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000372'
    tag gid: 'V-00207'
    tag rid: ''
    tag stig_id: 'SRG-APP-000372'
    tag fix_id: ''
    tag cci: ['CCI-002046']
    tag nist: ['AU-8 (1) (b)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Internal information system clock sync performed by cloud provider and is outside the Kubernetes scope.'
    end
end