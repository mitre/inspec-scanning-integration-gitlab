# encoding: UTF-8

control 'V-00004' do
    title 'The application must provide the capability for users to directly initiate a session lock.'
    desc  "A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence. 
	The session lock is implemented at the point where session activity can be determined. This is typically at the operating system-level, but may be at the application-level. Rather than be forced to wait for a period of time to expire before the user session can be locked, applications need to provide users with the ability to manually invoke a session lock so users may secure their application should the need arise for them to temporarily vacate the immediate physical vicinity."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000004'
    tag gid: 'V-00004'
    tag rid: ''
    tag stig_id: 'SRG-APP-000004'
    tag fix_id: ''
    tag cci: ['CCI-000058']
    tag nist: ['AC-11 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Application SRG/STIG should provide capability for sessesion locks.  Outside scope of Kubernetes Scope.'
    end
end