# encoding: UTF-8

control 'V-00204' do
    title 'The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.'
    desc  "If the audit reduction capability alters the content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.
	Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. 
	This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000369'
    tag gid: 'V-00204'
    tag rid: ''
    tag stig_id: 'SRG-APP-000369'
    tag fix_id: ''
    tag cci: ['CCI-001881']
    tag nist: ['AU-7 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit records storage and reduction are not in the Kubernetes scope.'
    end
end