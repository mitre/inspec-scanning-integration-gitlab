# encoding: UTF-8

control 'V-00275' do
    title 'The integrity verification application must automatically shut down the information system, restart the information system, and/or implement organization-defined security safeguards when integrity violations are discovered.'
    desc  "Unauthorized changes to software, firmware, and information can occur due to errors or malicious activity (e.g., tampering). Information includes metadata, such as security attributes associated with information. State-of-the-practice integrity-checking mechanisms (e.g., parity checks, cyclical redundancy checks, cryptographic hashes) and associated tools can automatically monitor the integrity of information systems and hosted applications.
	Organizations may define different integrity checking and anomaly responses by type of information (e.g., firmware, software, user data); by specific information (e.g., boot firmware, boot firmware for a specific types of machines); or a combination of both. Automatic implementation of specific safeguards within organizational information systems includes, for example, reversing the changes, halting the information system, restarting the information system, notification to the appropriate personnel or roles, or triggering audit alerts when unauthorized modifications to critical security files occur.
	This capability must take into account operational requirements for availability for selecting an appropriate response."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000480'
    tag gid: 'V-00275'
    tag rid: ''
    tag stig_id: 'SRG-APP-000480'
    tag fix_id: ''
    tag cci: ['CCI-002715']
    tag nist: ['SI-7 (5)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes is not an integrity verification application. '
    end
end