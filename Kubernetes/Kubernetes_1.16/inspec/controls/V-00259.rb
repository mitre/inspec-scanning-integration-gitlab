# encoding: UTF-8

control 'V-00259' do
    title 'The application must remove organization-defined software components after updated versions have been installed.'
    desc  "Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system."
    desc  'rationale', ''
    desc  'check', "To view all pods and the images used to create the pods, from the Master node, run the following command:
	kubectl get pods --all-namespaces -o jsonpath=\"{..image}\" |\
    tr -s '[[:space:]]' '\n' |\
    sort |\
    uniq -c
	
    Review the images used for pods running within Kubernetes.
	If there are multiple versions of the same image, this is a finding."
    desc  'fix', "Remove any old pods that are using older images.  On the Master node, run the command:
	kubectl delete pod podname
	Where podname is the name of the pod to delete."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000454'
    tag gid: 'V-00259'
    tag rid: ''
    tag stig_id: 'SRG-APP-000454'
    tag fix_id: ''
    tag cci: ['CCI-002617']
    tag nist: ['SI-2 (6)']

    kubectlGetImages = command("kubectl get pods --all-namespaces -o jsonpath=\"{..image}\" | tr -s '[[:space:]]' '\n' | sort | uniq -c").stdout

    describe 'This test can only be performed by manual examination.' do
        skip "Manual Check: Review the images used for pods running within Kubernetes. If there are multiple versions of the same image, this is a finding. List of Images in Kubernetes Instance:\n #{kubectlGetImages}"
    end
end