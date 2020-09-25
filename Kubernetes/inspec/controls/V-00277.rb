# encoding: UTF-8

control 'V-00277' do
    title 'The integrity verification application, upon detection of a potential integrity violation, must initiate one or more of the following actions: generate an audit record; alert the current user; alert organization-defined personnel or roles; and/or perform other organization-defined actions.'
    desc  "Without an audit capability, an integrity violation may not be detected. Organizations select response actions based on types of software, specific software, or information for which there are potential integrity violations. The integrity verification application must be configured to perform one or more of following actions: generates an audit record; alerts current user; alerts organization-defined personnel or roles. The organization may define additional actions to be taken."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000485'
    tag gid: 'V-00277'
    tag rid: ''
    tag stig_id: 'SRG-APP-000485'
    tag fix_id: ''
    tag cci: ['CCI-002724']
    tag nist: ['SI-7 (8)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: Kubernetes is not an integrity verification application. '
    end
end