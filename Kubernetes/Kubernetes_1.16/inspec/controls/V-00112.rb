# encoding: UTF-8

control 'V-00112' do
    title 'When using PKI-based authentication for user access, the application must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
    desc  "Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted. To meet this requirement, the information system must create trusted channels between itself and remote trusted authorized IT product (e.g., syslog server) entities that protect the confidentiality and integrity of communications. The information system must create trusted paths between itself and remote administrators and users that protect the confidentiality and integrity of communications.
	A trust anchor is an authoritative entity represented via a public key and associated data. It is most often used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. However, applications that do not use a trusted path are not approved for non-local and remote management of DoD information systems.
	Use of SSHv2 to establish a trusted channel is approved. Use of FTP, TELNET, HTTP, and SNMPV1 is not approved since they violate the trusted channel rule set. Use of web management tools that are not validated by common criteria my also violate trusted channel rule set.
	When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 
	This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000175'
    tag gid: 'V-00112'
    tag rid: ''
    tag stig_id: 'SRG-APP-000175'
    tag fix_id: ''
    tag cci: ['CCI-000185']
    tag nist: ['IA-5 (2) (a)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User authentication is performed by an external application defined by the organization.  Once authenticated, Kubernetes uses the authenticated user information to implement authorization to services.  Therefore, this requirement does not apply.'
    end
end