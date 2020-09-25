# encoding: UTF-8

control 'V-00281' do
    title 'The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.'
    desc  "Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
	Audit records can be generated from various components within the information system (e.g., module or policy filter)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000494'
    tag gid: 'V-00281'
    tag rid: ''
    tag stig_id: 'SRG-APP-000494'
    tag fix_id: ''
    tag cci: ['CCI-000172']
    tag nist: ['AU-12 c']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Categories of information and information levels are stored outside the Kubernetes scope.'
    end
end