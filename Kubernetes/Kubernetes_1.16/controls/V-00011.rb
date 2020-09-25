# encoding: UTF-8

control 'V-00011' do
    title 'The network element providing remote access services must use FIPS-validated digital signatures in conjunction with an approved hash function to protect the integrity of remote access sessions.'
    desc  "Without integrity protection, unauthorized changes may be made to the log files and reliable forensic analysis and discovery of the source of malicious system activity may be degraded.
	Remote access (e.g., Remote Desktop Protocol [RDP]) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
    Integrity checks include cryptographic checksums, digital signatures, and hash functions. Although digital signatures are one example of protecting integrity, this control is not intended to cause a new cryptographic hash to be generated every time a record is added to a log file. Integrity protections can also be implemented by using cryptographic techniques for security function isolation and file system protections to protect against unauthorized changes. 
	FIPS 186-4, Digital Signature Standard (DSS), specifies three NIST-approved digital signature algorithms: DSA, RSA, and ECDSA. All three are used to generate and verify digital signatures in conjunction with an approved hash function."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000015'
    tag gid: 'V-00011'
    tag rid: ''
    tag stig_id: 'SRG-APP-000015'
    tag fix_id: ''
    tag cci: ['CCI-001453']
    tag nist: ['AC-17 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Remote Access through external networks is outside the Kubernetes scope.'
    end
end 