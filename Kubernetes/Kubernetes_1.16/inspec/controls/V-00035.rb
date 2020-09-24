# encoding: UTF-8

control 'V-00035' do
    title 'The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
    desc  "To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 
	Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 
	This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions."
    desc  'rationale', ''
    desc  'check', "On the Master and Worker nodes, change to the /etc/sysconfig/ directory and run the command:
	grep -i staticPodPath kubelet
	If any of the nodes return a value for staticPodPath, this is a finding.
"
    desc  'fix', "Edit the kubelet file on each node under the /etc/sysconfig directory to remove the staticPodPath setting and restart the kubelet service by executing the command:
	service kubelet restart"
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000033'
    tag gid: 'V-00035'
    tag rid: ''
    tag stig_id: 'SRG-APP-000033'
    tag fix_id: ''
    tag cci: ['CCI-000213']
    tag nist: ['AC-3']

    describe file('/etc/sysconfig/kubelet') do
        its('content') { should_not match 'staticPodPath' }
    end
end