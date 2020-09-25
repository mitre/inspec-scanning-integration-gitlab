# encoding: UTF-8

control 'V-00160' do
    title 'The application must reveal error messages only to the IAO, IAM, and SA.'
    desc  "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the application. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.
	The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000267'
    tag gid: 'V-00160'
    tag rid: ''
    tag stig_id: 'SRG-APP-000267'
    tag fix_id: ''
    tag cci: ['CCI-001314']
    tag nist: ['SI-11 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Permissions to events and alerting is outside the Kubernetes scope.'
    end
end