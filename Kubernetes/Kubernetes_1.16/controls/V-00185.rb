# encoding: UTF-8

control 'V-00185' do
    title 'The application must utilize organization-defined data mining prevention techniques for organization-defined data storage objects to adequately protect against data mining.'
    desc  "Failure to protect organizational information from data mining may result in a compromise of information.
	Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000323'
    tag gid: 'V-00185'
    tag rid: ''
    tag stig_id: 'SRG-APP-000323'
    tag fix_id: ''
    tag cci: ['CCI-002346']
    tag nist: ['AC-23']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Data Mining falls outside the Kubernetes scope.'
    end
end