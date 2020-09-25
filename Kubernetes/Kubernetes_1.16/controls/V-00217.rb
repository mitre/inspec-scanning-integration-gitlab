# encoding: UTF-8

control 'V-00217' do
    title 'The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.'
    desc  "Control of application execution is a mechanism used to prevent execution of unauthorized applications. Some applications may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. 
	Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.
	Software program restrictions include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain application functionality based on organizationally defined criteria (e.g., privileges, subnets, sandboxed environments, roles)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000384'
    tag gid: 'V-00217'
    tag rid: ''
    tag stig_id: 'SRG-APP-000384'
    tag fix_id: ''
    tag cci: ['CCI-001764']
    tag nist: ['CM-7 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes is a runtime environment for containers.  Each service is necessary for the entire cluster to work correctly.  User containers would be controlled through authorization controls and any organization policies in place for container vetting.'
    end
end