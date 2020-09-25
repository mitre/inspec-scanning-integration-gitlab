# encoding: UTF-8

control 'V-00032' do
    title 'The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
    desc  "To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 
	Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 
	This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions."
    desc  'rationale', ''
    desc  'check', "Log into each worker node.  Verify that the sshd service is not enabled.  To validate that the service is not enabled, run the command:
	systemctl is-enabled sshd.service
	If the service sshd is enabled, this is a finding.
	Note: If console access is not available, SSH access can be attempted.  If the worker nodes cannot be reached, this mark this requirement as not a finding."
    desc  'fix', "To disable the sshd service, run the command:
	chkconfig sshd off
	Note: If access to the worker node is through an SSH session, it is important to realize there are two requirements for disabling and stopping the sshd service and they should be done during the same SSH session.  Disabling the service should be performed first and then stop the service to guarantee both settings can be made if the session were to be interrupted."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000033'
    tag gid: 'V-00032'
    tag rid: ''
    tag stig_id: 'SRG-APP-000033'
    tag fix_id: ''
    tag cci: ['CCI-000213']
    tag nist: ['AC-3']

    describe bash('sudo systemctl is-enabled sshd') do
        its('stdout') { should_not match 'enabled' }
    end
end 