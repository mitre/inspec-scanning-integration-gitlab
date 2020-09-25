# encoding: UTF-8

control 'V-00332' do
    title 'The application must validate certificates used for Transport Layer Security (TLS) functions by performing RFC 5280-compliant certification path validation.'
    desc  "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. 
	Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000605'
    tag gid: 'V-00332'
    tag rid: ''
    tag stig_id: 'SRG-APP-000605'
    tag fix_id: ''
    tag cci: ['CCI-000185']
    tag nist: ['IA-5 (2) (a)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes certificate use is for internal authentication between services.  User authentication, which this control talks about for PKI, happens with external organizational user authentication systems.  Any user services added to Kubernetes that need to authenticate users would need implement this control.'
    end
end