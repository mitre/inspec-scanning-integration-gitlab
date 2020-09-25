# encoding: UTF-8

control 'V-00080' do
    title 'The applications must limit privileges to change the software resident within software libraries.'
    desc  "If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.
	This requirement applies to applications with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications."
    desc  'rationale', ''
    desc  'check', "On the Master and worker nodes, change to the /etc/sysconfig directory.  Run the command:
	ls -l kubelet
	Each kubelet configuration file must have permissions of 644 or more restrictive.
	If any kubelet configuration file is less restrictive than 644, this is a finding.
	"
    desc  'fix', "On the Master node, change to the /etc/kubernetes/manifest directory.  Run the command:
	chmod 644 kubelet
	To verify the change took place, run the command:
	ls -l kubelet
	The kubelet file should now have the permissions of 644."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000133'
    tag gid: 'V-00080'
    tag rid: ''
    tag stig_id: 'SRG-APP-000133'
    tag fix_id: ''
    tag cci: ['CCI-001499']
    tag nist: ['CM-5 (6)']

    describe bash('stat -c %a  /etc/sysconfig/*kubelet* | awk \'$1>644\'') do
        its('stdout') { should be_empty }
        its('stderr') { should eq '' }
    end
end