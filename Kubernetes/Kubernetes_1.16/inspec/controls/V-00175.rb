# encoding: UTF-8

control 'V-00175' do
    title 'The application must display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
    desc  "If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.
	Information resources to which users gain access via authentication include, for example, local workstations, databases, and password-protected websites/web-based services. Logout messages for web page access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, file transfer protocol (FTP) sessions, information systems typically send logout messages as final messages prior to terminating sessions."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000297'
    tag gid: 'V-00175'
    tag rid: ''
    tag stig_id: 'SRG-APP-000297'
    tag fix_id: ''
    tag cci: ['CCI-002364']
    tag nist: ['AC-12 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User authentication is performed by an external application defined by the organization.  Once authenticated, Kubernetes uses the authenticated user information to implement authorization to services.  Login and logout functionality would be handled by the service authenticating users.'
    end
end