# encoding: UTF-8

control 'V-00229' do
    title 'The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.'
    desc  "Inappropriate access may be granted to unauthorized users if federal agency PIV credentials are not electronically verified. 
	Personal Identity Verification (PIV) credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000403'
    tag gid: 'V-00229'
    tag rid: ''
    tag stig_id: 'SRG-APP-000403'
    tag fix_id: ''
    tag cci: ['CCI-002010']
    tag nist: ['IA-8 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: PIV or CAC Validation falls oustide the Kubernetes scope.'
    end
end