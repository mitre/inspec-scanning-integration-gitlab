# encoding: UTF-8

control 'V-00119' do
    title 'The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.'
    desc  "If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as, system configuration details, diagnostic information, user information, and potentially sensitive application data. 
	Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.
	This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing \"ping,\" \"ls,\" \"ipconfig,\" or the hardware and software implementing the monitoring port of an Ethernet switch)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000185'
    tag gid: 'V-00119'
    tag rid: ''
    tag stig_id: 'SRG-APP-000185'
    tag fix_id: ''
    tag cci: ['CCI-000877']
    tag nist: ['MA-4 c']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Non-local maintenance of the Kubernetes control plane would be performed via a connection, such as SSH, to the OS or through a web frontend.  Therefore, any requirements for non-local maintenance would be handled within the OS or the web application STIG or SRG.'
    end
end