# encoding: UTF-8

control 'V-00111' do
    title 'The application must enforce a 60-day maximum password lifetime restriction.'
    desc  "Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 
	One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 
	This requirement does not include emergency administration accounts which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000174'
    tag gid: 'V-00111'
    tag rid: ''
    tag stig_id: 'SRG-APP-000174'
    tag fix_id: ''
    tag cci: ['CCI-000199']
    tag nist: ['IA-5 (1) (d)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes service account must utilize certificates for authentication.'
    end
end