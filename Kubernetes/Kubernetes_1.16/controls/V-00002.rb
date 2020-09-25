# encoding: UTF-8

control 'V-00002' do
    title 'The application must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
    desc  "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. 
	The session lock is implemented at the point where session activity can be determined. This is typically at the operating system-level, but may be at the application-level. 
	When the application design specifies the application rather than the operating system will determine when to lock the session, the application session lock event must include an obfuscation of the display screen so as to prevent other users from reading what was previously displayed. 
	Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000002'
    tag gid: 'V-00002'
    tag rid: ''
    tag stig_id: 'SRG-APP-000002'
    tag fix_id: ''
    tag cci: ['CCI-000060']
    tag nist: ['AC-11 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Session Management provided outside Kubernetes scope.'
    end
end