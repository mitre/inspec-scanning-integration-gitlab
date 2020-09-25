# encoding: UTF-8

control 'V-00001' do
    title 'The application must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
    desc  "Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.
	This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 
	This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system."
    desc  'rationale', ''
    desc  'check', " "
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000001'
    tag gid: 'V-00001'
    tag rid: ''
    tag stig_id: 'SRG-APP-000001'
    tag fix_id: ''
    tag cci: ['CCI-000054']
    tag nist: ['AC-10']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Network policies provided outside Kubernetes scope.'
    end
end