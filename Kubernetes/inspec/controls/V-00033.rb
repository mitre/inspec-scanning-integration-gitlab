# encoding: UTF-8

control 'V-00033' do
    title 'The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
    desc  "To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 
	Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 
	This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions."
    desc  'rationale', ''
    desc  'check', "From the master node, run the command:
	kubectl get pods --all-namespaces -l k8s-app=kubernetes-dashboard
	If any resources are returned, this is a finding."
    desc  'fix', "Delete the Kubernetes dashboard deployment with the following command:
	kubectl delete deployment kubernetes-dashboard --namespace=kube-system "
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000033'
    tag gid: 'V-00033'
    tag rid: ''
    tag stig_id: 'SRG-APP-000033'
    tag fix_id: ''
    tag cci: ['CCI-000213']
    tag nist: ['AC-3']

    describe bash('sudo kubectl get pods --all-namespaces -l k8s-app=kubernetes-dashboard') do
        its('stdout') { should be_empty }
        its('stderr') { should match 'No resources found' }
    end
end