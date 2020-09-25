# encoding: UTF-8

control 'V-00222' do
    title 'The application must electronically verify Personal Identity Verification (PIV) credentials.'
    desc  "The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.
	DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000392'
    tag gid: 'V-00222'
    tag rid: ''
    tag stig_id: 'SRG-APP-000392'
    tag fix_id: ''
    tag cci: ['CCI-001954']
    tag nist: ['IA-2 (12)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: PIV or CAC credential checks fall outside the Kubernetes scope.'
    end
end