# encoding: UTF-8

control 'V-00205' do
    title 'The application must provide a report generation capability that does not alter original content or time ordering of audit records.'
    desc  "If the audit report generation capability alters the original content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.
	The report generation capability provided by the application can generate customizable reports. 
	This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000370'
    tag gid: 'V-00205'
    tag rid: ''
    tag stig_id: 'SRG-APP-000370'
    tag fix_id: ''
    tag cci: ['CCI-001882']
    tag nist: ['AU-7 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit report capabilities fall outside the Kubernetes scope.'
    end
end