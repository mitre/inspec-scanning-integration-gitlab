# encoding: UTF-8

control 'V-00097' do
    title 'The application must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
    desc  "A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.
	An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 
	A non-privileged account is any operating system account with authorizations of a non-privileged user. 
	Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000157'
    tag gid: 'V-00097'
    tag rid: ''
    tag stig_id: 'SRG-APP-000157'
    tag fix_id: ''
    tag cci: ['CCI-001942']
    tag nist: ['IA-2 (9)']

    describe 'This check is Not Applicable.' do
        skip 'Network management is outside the Kubernetes STIG scope.'
    end
end