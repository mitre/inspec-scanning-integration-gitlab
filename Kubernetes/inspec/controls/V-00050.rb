# encoding: UTF-8

control 'V-00050' do
    title 'The application must generate audit records when successful/unsuccessful attempts to access privileges occur.'
    desc  "Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
	Audit records can be generated from various components within the information system (e.g., module or policy filter)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000091'
    tag gid: 'V-00050'
    tag rid: ''
    tag stig_id: 'SRG-APP-000091'
    tag fix_id: ''
    tag cci: ['CCI-000172']
    tag nist: ['AU-12 c']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User account management provided outside kubernetes control plane.  This control is Out of scope.'
    end
end