# encoding: UTF-8

control 'V-00274' do
    title 'The integrity verification application must perform an integrity check of organization-defined information at startup; at organization-defined transitional states or security-relevant events; or annually.'
    desc  "Unauthorized changes to information can occur due to errors or malicious activity (e.g., tampering). Information includes metadata, such as security attributes associated with information. State-of-the-practice integrity-checking mechanisms (e.g., parity checks, cyclical redundancy checks, cryptographic hashes) and associated tools can automatically monitor the integrity of information systems and hosted applications.
	Security-relevant events include, for example, the identification of a new threat to which organizational information systems are susceptible, and the installation of new hardware, software, or firmware. Transitional states include, for example, system startup, restart, shutdown, and abort.
	This requirement applies to integrity verification tools that are used to detect unauthorized changes to organization-defined information."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000477'
    tag gid: 'V-00274'
    tag rid: ''
    tag stig_id: 'SRG-APP-000477'
    tag fix_id: ''
    tag cci: ['CCI-002712']
    tag nist: ['SI-7 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes is not an integrity verification application. '
    end
end