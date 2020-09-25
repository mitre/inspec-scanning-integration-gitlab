# encoding: UTF-8

control 'V-00083' do
    title 'The application must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
    desc  "Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.
	Application communication sessions are protected utilizing transport encryption protocols, such as TLS. TLS provides web applications with a means to be able to authenticate user sessions and encrypt application traffic. Session authentication can be single (one way) or mutual (two way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other. 
	This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA). 
	This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of TLS mutual authentication (two-way/bidirectional)."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node.  Run the command:
	grep kube-apiserver.manifest -I -insecure-port
    grep kube-apiserver.manifest -I -secure-port
	grep kube-apiserver.manifest -I -etcd-servers *
    -edit manifest file:
    VIM <Manifest Name>
    Review  livenessProbe:
	 HttpGet:
	 Port:
    Review ports:
    -	containerPort:
	       hostPort:
    -	containerPort:
	       hostPort:
    Run Command:
    kubectl describe services �all-namespace
    Search labels for any apiserver names spaces.
    Port:
	Review the information systems documentation and interview the team, gain an understanding of the API Server architecture, and determine applicable ports, protocols, and services (PPS).  Any ports, protocols, and services not set in the system documentation is a finding.
	Review findings against the most recent PPSM Category Assurance List (CAL):
    https://cyber.mil/ppsm/cal/
	Verify API Server network boundary with the ports, protocols and services associated with the CAL Assurance Categories.  Any ports, protocols, and services not in compliance with the CAL Assurance Category requirements is a finding."
    desc  'fix', "Amend any system documentation requiring revision.   Update Kubernetes API Server manifest to comply with PPSM CAL ports, protocols, and services."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000142'
    tag gid: 'V-00083'
    tag rid: ''
    tag stig_id: 'SRG-APP-000142'
    tag fix_id: ''
    tag cci: ['CCI-000382']
    tag nist: ['CM-7 b']

    describe 'This test can only be performed by manual examination.' do
        skip 'Manual Check: Please check STIG for command reference.'
    end
end