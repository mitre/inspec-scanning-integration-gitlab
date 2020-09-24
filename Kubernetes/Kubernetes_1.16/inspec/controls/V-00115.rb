# encoding: UTF-8

control 'V-00115' do
    title 'The application must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
    desc  "To prevent the compromise of authentication information such as passwords during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 
	Obfuscation of user-provided information when typed into the system is a method used in addressing this risk. 
	For example, displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000178'
    tag gid: 'V-00115'
    tag rid: ''
    tag stig_id: 'SRG-APP-000178'
    tag fix_id: ''
    tag cci: ['CCI-000206']
    tag nist: ['IA-6']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User authentication is performed by an external application defined by the organization.  Once authenticated, Kubernetes uses the authenticated user information to implement authorization to services.  Therefore, this requirement does not apply.'
    end
end