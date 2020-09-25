# encoding: UTF-8

control 'V-00181' do
    title 'The application must terminate shared/group account credentials when members leave the group.'
    desc  "If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. A shared/group account credential is a shared form of authentication that allows multiple individuals to access the application using a single account. There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. Examples of credentials include passwords and group membership certificates."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000317'
    tag gid: 'V-00181'
    tag rid: ''
    tag stig_id: 'SRG-APP-000317'
    tag fix_id: ''
    tag cci: ['CCI-002142']
    tag nist: ['AC-2 (10)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: User management provided outside Kubernetes scope.'
    end
end