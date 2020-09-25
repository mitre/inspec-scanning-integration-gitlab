# encoding: UTF-8

control 'V-00142' do
    title 'The application must protect the authenticity of communications sessions.'
    desc  "Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.
	Application communication sessions are protected utilizing transport encryption protocols, such as TLS. TLS provides web applications with a means to be able to authenticate user sessions and encrypt application traffic. Session authentication can be single (one way) or mutual (two way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other. 
	This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA). 
	This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of TLS mutual authentication (two-way/bidirectional)."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i etcd-certfile * 
	If the setting etcd-certfile is not set in the Kubernetes API Server manifest file, this is a finding."
    desc  'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the value of --etcd-certfile to the certificate to be used for communication with etcd."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000219'
    tag gid: 'V-00142'
    tag rid: ''
    tag stig_id: 'SRG-APP-000219'
    tag fix_id: ''
    tag cci: ['CCI-001184']
    tag nist: ['SC-23']

    describe file('/etc/kubernetes/manifests/kube-apiserver.manifest') do
        its('content') { should match 'etcd-certfile' }
    end
end