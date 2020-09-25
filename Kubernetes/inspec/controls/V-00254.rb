# encoding: UTF-8

control 'V-00254' do
    title 'The application must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution Systems (PDS).'
    desc  "Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes. 
	This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.
	Alternative physical protection measures include PDS. PDSs are used to transmit unencrypted classified National Security Information (NSI) through an area of lesser classification or control. Since the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000440'
    tag gid: 'V-00254'
    tag rid: ''
    tag stig_id: 'SRG-APP-000440'
    tag fix_id: ''
    tag cci: ['CCI-002421']
    tag nist: ['SC-8 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Physical security and packets modification (Network layer) are outside the Kubernetes scope.'
    end
end