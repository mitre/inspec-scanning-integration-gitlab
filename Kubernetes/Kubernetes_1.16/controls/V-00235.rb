# encoding: UTF-8

control 'V-00235' do
    title 'Applications used for non-local maintenance sessions must verify remote disconnection at the termination of non-local maintenance and diagnostic sessions.'
    desc  "If the remote connection is not closed and verified as closed, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Remote connections must be disconnected and verified as disconnected when non-local maintenance sessions have been terminated and are no longer available for use."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000413'
    tag gid: 'V-00235'
    tag rid: ''
    tag stig_id: 'SRG-APP-000413'
    tag fix_id: ''
    tag cci: ['CCI-002891']
    tag nist: ['MA-4 (7)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: Network management for non-local maintenance falls outside the scope of Kubernetes scope.'
    end
end