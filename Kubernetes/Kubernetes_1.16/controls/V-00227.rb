# encoding: UTF-8

control 'V-00227' do
    title 'The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
    desc  "Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000401'
    tag gid: 'V-00227'
    tag rid: ''
    tag stig_id: 'SRG-APP-000401'
    tag fix_id: ''
    tag cci: ['CCI-001991']
    tag nist: ['IA-5 (2) (d)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: PKI-based authentication falls outside the Kubernetes scope.'
    end
end