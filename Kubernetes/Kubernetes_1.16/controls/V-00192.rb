# encoding: UTF-8

control 'V-00192' do
    title 'The application must automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
    desc  "By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000345'
    tag gid: 'V-00192'
    tag rid: ''
    tag stig_id: 'SRG-APP-000345'
    tag fix_id: ''
    tag cci: ['CCI-002238']
    tag nist: ['AC-7 b']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: User management provided by application outside Kubernetes scope.  Kubernetes service account utilize certificates for authentication.'
    end
end