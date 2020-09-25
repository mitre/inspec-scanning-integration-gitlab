# encoding: UTF-8

control 'V-00005' do
    title 'The application must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
    desc  "A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence. 
	The session lock is implemented at the point where session activity can be determined. This is typically determined and performed at the operating system-level, but in some instances it may be at the application-level. 
	Regardless of where the session lock is determined and implemented, once invoked the session lock must remain in place until the user re-authenticates. No other system or application activity aside from re-authentication must unlock the system. "
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000005'
    tag gid: 'V-00005'
    tag rid: ''
    tag stig_id: 'SRG-APP-000005'
    tag fix_id: ''
    tag cci: ['CCI-000056']
    tag nist: ['AC-11 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Session Management provided outside Kubernetes scope.'
    end
end