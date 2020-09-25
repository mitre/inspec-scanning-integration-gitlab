# encoding: UTF-8

control 'V-00246' do
    title 'The application must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.'
    desc  "Applications handling data requiring \"data at rest\" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
	Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000428'
    tag gid: 'V-00246'
    tag rid: ''
    tag stig_id: 'SRG-APP-000428'
    tag fix_id: ''
    tag cci: ['CCI-002475']
    tag nist: ['SC-28 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Central Storage provided by cloud provider is outside the Kubernetes scope.'
    end
end