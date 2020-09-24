# encoding: UTF-8

control 'V-00239' do
    title 'The application must provide an explicit indication of use to users physically present at collaborative computing devices.'
    desc  "An adversary may be able to gain access to information on whiteboards or listen to conversations on a microphone since collaboration equipment is typically not designed with the security access controls and protection measures of more sophisticated networked clients.
	Collaborative computing devices include, for example, networked whiteboards, cameras, and microphones. Explicit indication of use includes, for example, signals to users when collaborative computing devices are activated.
	This requirement applies to collaboration applications that control collaborative computing devices. This requirement is not intended to prohibit remote activation of centrally managed, dedicated VTC Suites for the purpose of remote testing of the equipment."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000418'
    tag gid: 'V-00239'
    tag rid: ''
    tag stig_id: 'SRG-APP-000418'
    tag fix_id: ''
    tag cci: ['CCI-001152']
    tag nist: ['SC-15 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Networked white boards, cameras, and microphones fall outside the Kubernetes scope.'
    end
end