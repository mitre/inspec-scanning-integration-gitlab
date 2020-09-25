# encoding: UTF-8

control 'V-00338' do
    title 'The application must prohibit or restrict the use of protocols that transmit unencrypted authentication information or use flawed cryptographic algorithm for transmission.'
    desc  "If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.
	This is applicable to nonlocal maintenance. Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the Internet) or an internal network. 
	Tools used for nonlocal management and diagnostics include Secure Shell (SSH) but may also include compatible enterprise maintenance and diagnostics servers. Regardless of the tool used, the device must permit only the use of protocols with the capability to be configured securely with integrity protections. Examples are POP3 and HTTP."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000645'
    tag gid: 'V-00338'
    tag rid: ''
    tag stig_id: 'SRG-APP-000645'
    tag fix_id: ''
    tag cci: ['CCI-000382']
    tag nist: ['CM-7 b']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Nonlocal maintenance would be through mechanisms offered by the hosting system such as ssh.  Kubernetes does not have a mechanism to attach nonlocally without going through the host itself.  Therefore, this requirement would be handled by the host OS.'
    end
end