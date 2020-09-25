# encoding: UTF-8

control 'V-00168' do
    title 'The application must use cryptographic mechanisms to protect the integrity of audit tools.'
    desc  "Protecting the integrity of the tools used for auditing purposes is a critical step to ensuring the integrity of audit data. Audit data includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 
	Audit tools include, but are not limited to, vendor provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.
	It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs. 
	To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated or replaced. An example is a checksum hash of the file or files."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000290'
    tag gid: 'V-00168'
    tag rid: ''
    tag stig_id: 'SRG-APP-000290'
    tag fix_id: ''
    tag cci: ['CCI-001496']
    tag nist: ['AU-9 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit tools fall outside the Kubernetes Scope.'
    end
end