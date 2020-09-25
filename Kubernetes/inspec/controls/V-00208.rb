# encoding: UTF-8

control 'V-00208' do
    title 'The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).'
    desc  "If time stamps are not consistently applied and there is no common time reference, it is difficult to perform forensic analysis.
	Time stamps generated by the application include date and time. Time is commonly expressed in Coordinated Universal Time (UTC), a modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000374'
    tag gid: 'V-00208'
    tag rid: ''
    tag stig_id: 'SRG-APP-000374'
    tag fix_id: ''
    tag cci: ['CCI-001890']
    tag nist: ['AU-8 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: The API server uses the time and time zone of the hosting operating system.  This parameter would be configured at the OS.'
    end
end