# encoding: UTF-8

control 'V-00195' do
    title 'The application must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
    desc  "In order to ensure applications have a sufficient storage capacity in which to write the audit logs, applications need to be able to allocate audit record storage capacity. 
	The task of allocating audit record storage capacity is usually performed during initial installation of the application and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000357'
    tag gid: 'V-00195'
    tag rid: ''
    tag stig_id: 'SRG-APP-000357'
    tag fix_id: ''
    tag cci: ['CCI-001849']
    tag nist: ['AU-4']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Central Storage is outside the Kubernetes scope.'
    end
end