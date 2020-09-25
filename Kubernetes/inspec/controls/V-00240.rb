# encoding: UTF-8

control 'V-00240' do
    title 'Applications that provide address resolution services must provide additional data integrity verification artifacts along with the authoritative name resolution data the system returns in response to external name/address resolution queries.'
    desc  "The major threat associated with Domain Name System (DNS) forged responses or failures are the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. This requirement enables remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service. 
	A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS to map between host/service names and network addresses must provide other means to assure the authenticity and integrity of response data. 
	This applies to those applications that provide a mapping between host/service names and network addresses.
	In the case of DNS, employ DNSSEC to provide an additional data origin authentication and integrity verification artifacts along with the authoritative data the system returns in response to DNS name/address resolution queries."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000422'
    tag gid: 'V-00240'
    tag rid: ''
    tag stig_id: 'SRG-APP-000422'
    tag fix_id: ''
    tag cci: ['CCI-002462']
    tag nist: ['SC-20 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: DNS address resolution falls outside the Kubernetes scope.'
    end
end