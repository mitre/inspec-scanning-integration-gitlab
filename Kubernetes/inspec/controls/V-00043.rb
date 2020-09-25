# encoding: UTF-8

control 'V-00043' do
    title 'The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
    desc  "The banner must be acknowledged by the user prior to allowing the user access to the application. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law. 
	To establish acceptance of the application usage policy, a click-through banner at application logon is required. The application must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating \"OK\"."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000069'
    tag gid: 'V-00043'
    tag rid: ''
    tag stig_id: 'SRG-APP-000069'
    tag fix_id: ''
    tag cci: ['CCI-000050']
    tag nist: ['AC-8 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes does not authenticate users.  It only authorizes uses as commands and actions are taken.  Exhibiting and banner would be performed by the OS or any user services executing within Kubernetes.'
    end
end