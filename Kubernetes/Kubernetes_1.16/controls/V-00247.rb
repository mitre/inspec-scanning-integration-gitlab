# encoding: UTF-8

control 'V-00247' do
    title 'The application must implement cryptographic mechanisms to prevent unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
    desc  "Applications handling data requiring \"data at rest\" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
	Selection of a cryptographic mechanism is based on the need to protect the confidentiality of organizational information. The strength of mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000429'
    tag gid: 'V-00247'
    tag rid: ''
    tag stig_id: 'SRG-APP-000429'
    tag fix_id: ''
    tag cci: ['CCI-002476']
    tag nist: ['SC-28 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Information configuration files are stored on the hosting system OS.  The OS is responsible for the control.'
    end
end