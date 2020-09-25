# encoding: UTF-8

control 'V-00242' do
    title 'Applications that perform address resolution services must request data integrity verification on the name/address resolution responses the system receives from authoritative sources.'
    desc  "If data origin authentication and data integrity verification is not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed which would result in query failure or denial of service. Data integrity verification must be performed to thwart these types of attacks.
	Each client of name resolution services either performs this validation on its own, or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations. 
	This applies to DNS clients and recursive resolving and/or caching DNS servers."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000424'
    tag gid: 'V-00242'
    tag rid: ''
    tag stig_id: 'SRG-APP-000424'
    tag fix_id: ''
    tag cci: ['CCI-002466']
    tag nist: ['SC-21']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: DNS services provided outside the Kubernetes scope.'
    end
end