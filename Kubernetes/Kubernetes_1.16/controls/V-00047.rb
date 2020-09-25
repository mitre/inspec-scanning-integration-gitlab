# encoding: UTF-8

control 'V-00047' do
    title 'For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.'
    desc  "Without the ability to collate records based on the time when the events occurred, the ability to perform forensic analysis and investigations across multiple components is significantly degraded.
	Audit trails are time-correlated if the time stamps in the individual audit records can be reliably related to the time stamps in other audit records to achieve a time ordering of the records within organization-defined level of tolerance.
	This requirement applies only to applications which provide the capability to compile system-wide audit records for multiple systems or system components."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000086'
    tag gid: 'V-00047'
    tag rid: ''
    tag stig_id: 'SRG-APP-000086'
    tag fix_id: ''
    tag cci: ['CCI-000174']
    tag nist: ['AU-12 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: The Kubernetes is not a log aggregation system.  Kubernetes send logs to an external log server which would aggregate log data.'
    end
end