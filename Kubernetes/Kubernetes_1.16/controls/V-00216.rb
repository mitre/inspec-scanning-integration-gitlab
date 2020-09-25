# encoding: UTF-8

control 'V-00216' do
    title 'The application must disable organization-defined functions, ports, protocols, and services (within the application) deemed unnecessary and/or non-secure.'
    desc  "Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.
	The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure. "
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000383'
    tag gid: 'V-00216'
    tag rid: ''
    tag stig_id: 'SRG-APP-000383'
    tag fix_id: ''
    tag cci: ['CCI-001762']
    tag nist: ['CM-7 (1) (b)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes is a runtime environment for containers.  Each service is necessary for the entire cluster to work correctly.  Other requirements within the STIG have already been addressed to put Kubernetes on secure ports.  User containers would be controlled through authorization controls and any organization policies in place for container vetting, which would include port utilization.'
    end
end