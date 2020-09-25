# encoding: UTF-8

control 'V-00118' do
    title 'The information system must provide an audit reduction capability that supports on-demand reporting requirements.'
    desc  "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 
	Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as-needed) reports.
	This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000181'
    tag gid: 'V-00118'
    tag rid: ''
    tag stig_id: 'SRG-APP-000181'
    tag fix_id: ''
    tag cci: ['CCI-001876']
    tag nist: ['AU-7 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit reduction and reporting capabilities are outside the Kubernetes scope.'
    end
end