# encoding: UTF-8

control 'V-00230' do
    title 'The application must accept FICAM-approved third-party credentials.'
    desc  "Access may be denied to legitimate users if FICAM-approved third-party credentials are not accepted. 
	This requirement typically applies to organizational information systems that are accessible to non-federal government agencies and other partners. This allows federal government relying parties to trust such credentials at their approved assurance levels.
	Third-party credentials are those credentials issued by non-federal government entities approved by the Federal Identity, Credential, and Access Management (FICAM) Trust Framework Solutions initiative."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000404'
    tag gid: 'V-00230'
    tag rid: ''
    tag stig_id: 'SRG-APP-000404'
    tag fix_id: ''
    tag cci: ['CCI-002011']
    tag nist: ['IA-8 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: FICAM credentials are outside Kubernetes scope.'
    end
end