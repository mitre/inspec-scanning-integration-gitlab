# encoding: UTF-8

control 'V-00231' do
    title 'The application must conform to FICAM-issued profiles.'
    desc  "Without conforming to FICAM-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.
	This requirement addresses open identity management standards."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000405'
    tag gid: 'V-00231'
    tag rid: ''
    tag stig_id: 'SRG-APP-000405'
    tag fix_id: ''
    tag cci: ['CCI-002014']
    tag nist: ['IA-8 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: FICAM operates outside the Kubernetes scope.'
    end
end