# encoding: UTF-8

control 'V-00122' do
    title 'The application must prohibit remote activation of collaborative computing devices. (Centrally managed, dedicated VTC suites located in approved VTC locations are excluded from this requirement.)'
    desc  "An adversary may be able to gain access to information on whiteboards or listen to conversations on a microphone since collaboration equipment is typically not designed with security access controls and protection measures of more sophisticated networked clients.
	Collaborative computing devices include, for example, networked whiteboards, cameras, and microphones.
	This requirement applies to collaboration applications that control collaborative computing devices. This requirement is not intended to prohibit remote activation of centrally managed, dedicated VTC Suites for the purpose of remote testing of the equipment."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000202'
    tag gid: 'V-00122'
    tag rid: ''
    tag stig_id: 'SRG-APP-000202'
    tag fix_id: ''
    tag cci: ['CCI-001150']
    tag nist: ['SC-15 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Network management falls outside the scope of Kubernetes scope.'
    end
end