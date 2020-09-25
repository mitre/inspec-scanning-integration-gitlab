# encoding: UTF-8

control 'V-00292' do
    title 'The application must generate audit records showing starting and ending time for user access to the system.'
    desc  "Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
	Audit records can be generated from various components within the information system (e.g., module or policy filter)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000505'
    tag gid: 'V-00292'
    tag rid: ''
    tag stig_id: 'SRG-APP-000505'
    tag fix_id: ''
    tag cci: ['CCI-000172']
    tag nist: ['AU-12 c']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Users to Kubernetes cause events to occur for actions to take place.  The time involved for the session used to take the action is tracked in other audit requirements.  The entire session, ssh or console, is not logged by Kubernetes.  This would be done by the OS.'
    end
end