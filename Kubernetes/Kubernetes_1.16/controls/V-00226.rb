# encoding: UTF-8

control 'V-00226' do
    title 'The application must prohibit the use of cached authenticators after an organization-defined time period.'
    desc  "If cached authentication information is out of date, the validity of the authentication information may be questionable."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000400'
    tag gid: 'V-00226'
    tag rid: ''
    tag stig_id: 'SRG-APP-000400'
    tag fix_id: ''
    tag cci: ['CCI-002007']
    tag nist: ['IA-5 (13)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: Network management provided outside Kubernetes scope.'
    end
end