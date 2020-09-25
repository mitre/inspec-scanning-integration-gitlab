# encoding: UTF-8

control 'V-00202' do
    title 'The application must provide a report generation capability that supports on-demand reporting requirements.'
    desc  "The report generation capability must support on-demand reporting in order to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents
	The report generation capability provided by the application must be capable of generating on-demand (i.e., customizable, ad-hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective. 
	This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand reporting requirements."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000367'
    tag gid: 'V-00202'
    tag rid: ''
    tag stig_id: 'SRG-APP-000367'
    tag fix_id: ''
    tag cci: ['CCI-001879']
    tag nist: ['AU-7 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit report capabilities fall outside the Kubernetes scope.'
    end
end