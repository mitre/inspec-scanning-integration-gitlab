# encoding: UTF-8

control 'V-00233' do
    title 'Applications used for nonlocal maintenance sessions must use FIPS-validated keyed-hash message authentication code (HMAC) to protect the integrity of nonlocal maintenance and diagnostic communications.'
    desc  "Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.
	Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the Internet) or an internal network. 
	Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.
	Separate requirements for configuring applications and protocols used by each product (e.g., SNMPv3, SSHv2, NTP, and other protocols and applications that require server/client authentication) are required to implement this requirement. The SSHv2 protocol suite must be mandated in the product because it includes Layer 7 protocols such as SCP and SFTP that can be used for secure file transfers."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000411'
    tag gid: 'V-00233'
    tag rid: ''
    tag stig_id: 'SRG-APP-000411'
    tag fix_id: ''
    tag cci: ['CCI-002890']
    tag nist: ['MA-4 (6)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Any requirements for tools used for nonlocal maintenance are outside the Kubernetes scope.'
    end
end