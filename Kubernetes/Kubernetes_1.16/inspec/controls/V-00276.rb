# encoding: UTF-8

control 'V-00276' do
    title 'The integrity verification application must audit detected potential integrity violations.'
    desc  "Without an audit capability, an integrity violation may not be detected. Organizations select response actions based on types of software, specific software, or information for which there are potential integrity violations. The integrity verification application must have the capability to audit and it must be enabled."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000484'
    tag gid: 'V-00276'
    tag rid: ''
    tag stig_id: 'SRG-APP-000484'
    tag fix_id: ''
    tag cci: ['CCI-002723']
    tag nist: ['SI-7 (8)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: Kubernetes is not an integrity verification application. '
    end
end