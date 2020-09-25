# encoding: UTF-8

control 'V-00273' do
    title 'The integrity verification application must perform an integrity check of organization-defined firmware at startup; at organization-defined transitional states or security-relevant events; or annually.'
    desc  "Unauthorized changes to firmware can occur due to errors or malicious activity (e.g., tampering). Firmware includes, for example, the Basic Input Output System (BIOS). State-of-the-practice integrity-checking mechanisms (e.g., parity checks, cyclical redundancy checks, cryptographic hashes) and associated tools can automatically monitor the integrity of information systems and hosted applications.
	Security-relevant events include, for example, the identification of a new threat to which organizational information systems are susceptible, and the installation of new hardware, software, or firmware. Transitional states include, for example, system startup, restart, shutdown, and abort.
	This requirement applies to integrity verification tools that are used to detect unauthorized changes to organization-defined firmware."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000476'
    tag gid: 'V-00273'
    tag rid: ''
    tag stig_id: 'SRG-APP-000476'
    tag fix_id: ''
    tag cci: ['CCI-002711']
    tag nist: ['SI-7 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Hardware maintenance falls outside the Kubernetes scope.'
    end
end