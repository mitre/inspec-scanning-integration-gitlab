# encoding: UTF-8

control 'V-00065' do
    title 'The applications must provide the capability to filter audit records for events of interest based upon organization-defined criteria.'
    desc  "The ability to specify the event criteria that are of interest provides the persons reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded. 
	Events of interest can be identified by the content of specific audit record fields including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations may define audit event criteria to any degree of granularity required, for example, locations selectable by general networking location (e.g., by network or subnetwork) or selectable by specific information system component. This requires applications to provide the capability to customize audit record reports based on organization-defined criteria."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000115'
    tag gid: 'V-00065'
    tag rid: ''
    tag stig_id: 'SRG-APP-000115'
    tag fix_id: ''
    tag cci: ['CCI-000158']
    tag nist: ['AU-7 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit filtering outside the scope of Kubernetes.'
    end
end