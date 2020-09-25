# encoding: UTF-8

control 'V-00046' do
    title 'The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
    desc  "Without non-repudiation, it is impossible to positively attribute an action to an individual (or process acting on behalf of an individual). 
	Non-repudiation services can be used to determine if information originated from a particular individual, or if an individual took specific actions (e.g., sending an email, signing a contract, approving a procurement request) or received specific information. Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. The application will be configured to provide non-repudiation services for an organization-defined set of commands that are used by the user (or processes action on behalf of the user).
	DoD PKI provides for non-repudiation through the use of digital signatures. Non-repudiation requirements will vary from one application to another and will be defined based on application functionality, data sensitivity and mission requirements."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000080'
    tag gid: 'V-00046'
    tag rid: ''
    tag stig_id: 'SRG-APP-000080'
    tag fix_id: ''
    tag cci: ['CCI-000166']
    tag nist: ['AU-10']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Non-repudiation services is not a part of the Kuberenetes scope.'
    end
end