# encoding: UTF-8

control 'V-00003' do
    title 'The application must initiate a session lock after a 15-minute period of inactivity.'
    desc  "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.
	The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system-level and results in a system lock, but may be at the application-level where the application interface window is secured instead. "
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000003'
    tag gid: 'V-00003'
    tag rid: ''
    tag stig_id: 'SRG-APP-000003'
    tag fix_id: ''
    tag cci: ['CCI-000057']
    tag nist: ['AC-11 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Session Management provided outside Kubernetes scope.'
    end
end