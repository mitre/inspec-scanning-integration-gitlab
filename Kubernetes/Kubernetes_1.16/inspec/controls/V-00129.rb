# encoding: UTF-8

control 'V-00129' do
    title 'Applications that provide address resolution services, when operating as part of a distributed, hierarchical namespace, must provide the means to indicate the security status of child zones.'
    desc  "If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With Domain Name System (DNS), the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down.
	A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS to map between host/service names and network addresses must provide other means to assure the authenticity and integrity of response data. 
	This applies to those applications that provide a mapping between host/service names and network addresses."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000214'
    tag gid: 'V-00129'
    tag rid: ''
    tag stig_id: 'SRG-APP-000214'
    tag fix_id: ''
    tag cci: ['CCI-001179']
    tag nist: ['SC-20 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: DNS services is outside the Kubernetes scope.'
    end
end