# encoding: UTF-8

control 'V-00174' do
    title 'Applications requiring user access authentication must provide a logout capability for user initiated communication session.'
    desc  "If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.
	Information resources to which users gain access via authentication include, for example, local workstations, databases, and password-protected websites/web-based services. However, for some types of interactive sessions including, for example, file transfer protocol (FTP) sessions, information systems typically send logout messages as final messages prior to terminating sessions."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000296'
    tag gid: 'V-00174'
    tag rid: ''
    tag stig_id: 'SRG-APP-000296'
    tag fix_id: ''
    tag cci: ['CCI-002363']
    tag nist: ['AC-12 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Application management falls outside Kubernetes scope.'
    end
end