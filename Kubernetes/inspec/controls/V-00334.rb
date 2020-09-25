# encoding: UTF-8

control 'V-00334' do
    title 'The application must use a FIPS-validated block cipher mode to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
    desc  "Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.
	Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the Internet) or an internal network. 
 
    To protect the confidentiality of nonlocal maintenance sessions, the following cipher block modes are NIST approved. Currently, NIST has approved the following confidentiality modes to be used with approved block ciphers in a series of special publications: ECB, CBC, OFB, CFB, CTR, XTS-AES, FF1, FF3,CCM, GCM, KW, KWP, and TKW."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000620'
    tag gid: 'V-00334'
    tag rid: ''
    tag stig_id: 'SRG-APP-000620'
    tag fix_id: ''
    tag cci: ['CCI-003123']
    tag nist: ['MA-4 (6)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Non-local maintenance session control and crypto would be handled by the OS or an application such as SSH and not the Kubernetes directly.'
    end
end