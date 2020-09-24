# encoding: UTF-8

control 'V-00298' do
    title 'The application must use a FIPS-validated cryptographic module to generate cryptographic hashes.'
    desc  "FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard. 
	The cryptographic module used must have at least one validated hash algorithm. This validated hash algorithm must be used to generate cryptographic hashes for all cryptographic security function within the product being evaluated."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000514'
    tag gid: 'V-00298'
    tag rid: ''
    tag stig_id: 'SRG-APP-000514'
    tag fix_id: ''
    tag cci: ['CCI-002450']
    tag nist: ['SC-13']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes does not contain confidential data, such as PII, unless a user service deployed within Kubernetes operates on this type of data.  If a user service is deployed that operates on confidential data, the service would need to implement this control.'
    end
end