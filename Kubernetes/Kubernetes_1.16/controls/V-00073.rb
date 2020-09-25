# encoding: UTF-8

control 'V-00073' do
    title 'The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
    desc  "Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained. 
	This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.
	This requirement only applies to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000125'
    tag gid: 'V-00073'
    tag rid: ''
    tag stig_id: 'SRG-APP-000125'
    tag fix_id: ''
    tag cci: ['CCI-001348']
    tag nist: ['AU-9 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit record backups are performed outside the scope of the Kubernetes Control Plane scope.'
    end
end