# encoding: UTF-8

control 'V-00228' do
    title 'The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.'
    desc  "Access may be denied to authorized users if federal agency PIV credentials are not accepted. 
	Personal Identity Verification (PIV) credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000402'
    tag gid: 'V-00228'
    tag rid: ''
    tag stig_id: 'SRG-APP-000402'
    tag fix_id: ''
    tag cci: ['CCI-002009']
    tag nist: ['IA-8 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Authentication of users is handled by organization defined external resources.  Kubernetes then uses the authenticated user to determine authorization of services.'
    end
end