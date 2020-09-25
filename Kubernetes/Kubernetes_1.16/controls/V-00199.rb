# encoding: UTF-8

control 'V-00199' do
    title 'The application must provide an audit reduction capability that supports on-demand audit review and analysis.'
    desc  "The ability to perform on-demand audit review and analysis, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 
	Audit reduction is a technique used to reduce the volume of audit records in order to facilitate a manual review. Audit reduction does not alter original audit records. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as-needed) reports.
	This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000364'
    tag gid: 'V-00199'
    tag rid: ''
    tag stig_id: 'SRG-APP-000364'
    tag fix_id: ''
    tag cci: ['CCI-001875']
    tag nist: ['AU-7 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit capabilities fall oustide the Kubernetes scope.'
    end
end