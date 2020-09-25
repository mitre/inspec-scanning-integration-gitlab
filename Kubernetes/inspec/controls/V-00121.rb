# encoding: UTF-8

control 'V-00121' do
    title 'The application must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements.'
    desc  "Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 
	Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/sysconfig/ directory on the Kubernetes Master Node.  Run the command:
	more kubelet  
    --streaming-connection-idle-timeout
	If the setting streaming-connection-idle-timeouth is set to 0 or parameter not set in the Kubernetes Kubelet, this is a finding.
	"
    desc  'fix', "Edit the Kubernetes Kuberlet file in the /etc/sysconfig directory on the Kubernetes Master Node.  Set the argument --streaming-connection-idle-timeout other than 0.  Reset Kubelet servvice using the following command:
	service kubelet restart
	
    Reset Kubelet servvice using the following command:
	service kubelet restart"
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000190'
    tag gid: 'V-00121'
    tag rid: ''
    tag stig_id: 'SRG-APP-000190'
    tag fix_id: ''
    tag cci: ['CCI-001133']
    tag nist: ['SC-10']

    describe file('/etc/sysconfig/kubelet') do
        its('content') { should_not match '--streaming-connection-idle-timeout=0' }
        its('content') { should_not match '' }
    end
end