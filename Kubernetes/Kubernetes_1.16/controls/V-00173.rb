# encoding: UTF-8

control 'V-00173' do
    title 'The application must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
    desc  "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.
	Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 
	Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.
	This capability is typically reserved for specific application system functionality where the system owner, data owner, or organization requires additional assurance. Based upon requirements and events specified by the data or application owner, the application developer must incorporate logic into the application that will provide a control mechanism that disconnects users upon the defined event trigger. The methods for incorporating this requirement will be determined and specified on a case by case basis during the application design and development stages."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000295'
    tag gid: 'V-00173'
    tag rid: ''
    tag stig_id: 'SRG-APP-000295'
    tag fix_id: ''
    tag cci: ['CCI-002361']
    tag nist: ['AC-12']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Network and application management falls outside the Kubernetes scope.'
    end
end