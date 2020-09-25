# encoding: UTF-8

control 'V-00069' do
    title 'The application must protect audit information from unauthorized deletion.'
    desc  "If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 
	To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. 
	Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 
	Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.
	Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. Audit information may include data from other applications or be included with the audit application itself."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000120'
    tag gid: 'V-00069'
    tag rid: ''
    tag stig_id: 'SRG-APP-000120'
    tag fix_id: ''
    tag cci: ['CCI-000164']
    tag nist: ['AU-9']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit information will be stored outside the Kubernetes Control Plane scope.'
    end
end