# encoding: UTF-8

control 'V-00074' do
    title 'The application must use cryptographic mechanisms to protect the integrity of log information.'
    desc  "Without integrity protection, unauthorized changes may be made to the log files and reliable forensic analysis and discovery of the source of malicious system activity may be degraded.
	Integrity checks include cryptographic checksums, digital signatures, and hash functions. Although digital signatures are one example of protecting integrity, this control is not intended to cause a new cryptographic hash to be generated every time a record is added to a log file. Integrity protections can also be implemented by using cryptographic techniques for security function isolation and file system protections to protect against unauthorized changes. "
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000126'
    tag gid: 'V-00074'
    tag rid: ''
    tag stig_id: 'SRG-APP-000126'
    tag fix_id: ''
    tag cci: ['CCI-001350']
    tag nist: ['AU-9 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes uses the hosting filesystem for audit log storage.   The use of cryptographic mechanisms to protect the integrity of log information  would be implemented at the hosting system hardware or OS level and not by Kubernetes.'
    end
end