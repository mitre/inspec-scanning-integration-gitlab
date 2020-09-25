# encoding: UTF-8

control 'V-00076' do
    title 'The applications must limit privileges to change the software resident within software libraries.'
    desc  "If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.
	This requirement applies to applications with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications."
    desc  'rationale', ''
    desc  'check', "On the Master and each Worker node, change to the /etc/sysconfig/ directory and run the command:
	grep -i hostname-override kubelet  
--hostname-override
	If any of the nodes have the setting hostname-override present, this is a finding."
    desc  'fix', "Edit the Kubernetes Kuberlet file in the /etc/sysconfig directory on the Master and Worker nodes and remove the --hostname-override setting.  Restart the service after the change is made by running:
	service kubelet restart  "
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000133'
    tag gid: 'V-00076'
    tag rid: ''
    tag stig_id: 'SRG-APP-000133'
    tag fix_id: ''
    tag cci: ['CCI-001499']
    tag nist: ['CM-5 (6)']

    describe file('/etc/sysconfig/kubelet') do
        its('content') { should_not match '--hostname-override' }
    end
end
