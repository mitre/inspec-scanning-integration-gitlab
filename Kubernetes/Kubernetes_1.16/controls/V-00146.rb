# encoding: UTF-8

control 'V-00146' do
    title 'Applications must recognize only system-generated session identifiers.'
    desc  "Applications utilize sessions and session identifiers to control application behavior and user access. If an attacker can guess the session identifier, or can inject or manually insert session information, the session may be compromised.
	Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.
	This requirement focuses on communications protection for the application session rather than for the network packet. This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000223'
    tag gid: 'V-00146'
    tag rid: ''
    tag stig_id: 'SRG-APP-000223'
    tag fix_id: ''
    tag cci: ['CCI-001664']
    tag nist: ['SC-23 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Network management falls outside the scope of Kubernetes scope.'
    end
end