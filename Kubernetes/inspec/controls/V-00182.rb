# encoding: UTF-8

control 'V-00182' do
    title 'The application must enforce organization-defined circumstances and/or usage conditions for organization-defined accounts.'
    desc  "Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.
	Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the application must be configured to enforce the specific conditions or circumstances under which application accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000318'
    tag gid: 'V-00182'
    tag rid: ''
    tag stig_id: 'SRG-APP-000318'
    tag fix_id: ''
    tag cci: ['CCI-002145']
    tag nist: ['AC-2 (11)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User account management provided outside Kubernetes scope.'
    end
end