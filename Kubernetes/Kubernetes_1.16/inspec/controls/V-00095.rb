# encoding: UTF-8

control 'V-00095' do
    title 'The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.'
    desc  "To assure individual accountability and prevent unauthorized access, application users must be individually identified and authenticated. 
	Individual accountability mandates that each user is uniquely identified. A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the application using a single account. 
	If an application allows or provides for group authenticators, it must first individually authenticate users prior to implementing group authenticator functionality. 
	Some applications may not have the need to provide a group authenticator; this is considered a matter of application design. In those instances where the application design includes the use of a group authenticator, this requirement will apply.
	There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. An example of this type of access is a web server which contains publicly releasable information."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000153'
    tag gid: 'V-00095'
    tag rid: ''
    tag stig_id: 'SRG-APP-000153'
    tag fix_id: ''
    tag cci: ['CCI-000770']
    tag nist: ['IA-2 (5)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User authentication is performed by an external application defined by the organization.  Once authenticated, Kubernetes uses the authenticated user information to implement authorization to services.  Therefore, this requirement does not apply.'
    end
end