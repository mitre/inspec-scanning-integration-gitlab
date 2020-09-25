# encoding: UTF-8

control 'V-00068' do
    title 'The application must protect audit information from unauthorized modification.'
    desc  "If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 
	To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. 
	This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations. 
	Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.
	Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000119'
    tag gid: 'V-00068'
    tag rid: ''
    tag stig_id: 'SRG-APP-000119'
    tag fix_id: ''
    tag cci: ['CCI-000163']
    tag nist: ['AU-9']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit information will be stored outside the Kubernetes Control Plane scope.'
    end
end