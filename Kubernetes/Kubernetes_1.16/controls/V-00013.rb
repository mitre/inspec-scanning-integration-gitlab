# encoding: UTF-8

control 'V-00013' do
    title 'The application must provide automated mechanisms for supporting account management functions.'
    desc  "Enterprise environments make application account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. 
	A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended or terminated or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.
	The application must be configured to automatically provide account management functions and these functions must immediately enforce the organization's current account policy. The automated mechanisms may reside within the application itself or may be offered by the operating system or other infrastructure providing automated account management capabilities. Automated mechanisms may be comprised of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements. 
	Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage."
    desc  'rationale', ''
    desc  'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Run the command:
	grep -i use-service-account-credential * 
	If the setting use-service-account-credential is not set in the Kubernetes Controller Manager manifest file or it is set to false, this is a finding."
    desc  'fix', "Edit the Kubernetes Controller Manager manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.  Set the value of use-service-account-credentials to true."
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000023'
    tag gid: 'V-00013'
    tag rid: ''
    tag stig_id: 'SRG-APP-000023'
    tag fix_id: ''
    tag cci: ['CCI-000015']
    tag nist: ['AC-2 (1)']

    describe file('/etc/kubernetes/manifests/kube-controller-manager.manifest') do
        its('content') { should match 'use-service-account-credentials=true' }
    end
end  