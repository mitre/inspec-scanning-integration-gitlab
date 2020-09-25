# encoding: UTF-8

control 'V-00041' do
    title 'The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
    desc  "By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. "
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000065'
    tag gid: 'V-00041'
    tag rid: ''
    tag stig_id: 'SRG-APP-000065'
    tag fix_id: ''
    tag cci: ['CCI-000044']
    tag nist: ['AC-7 a']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: User management provided outside Kubernetes scope.'
    end
end