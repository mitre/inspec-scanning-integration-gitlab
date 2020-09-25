# encoding: UTF-8

control 'V-00106' do
    title 'The application must require the change of at least 15 of the total number of characters when passwords are changed.'
    desc  "If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.
	The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000170'
    tag gid: 'V-00106'
    tag rid: ''
    tag stig_id: 'SRG-APP-000170'
    tag fix_id: ''
    tag cci: ['CCI-000195']
    tag nist: ['IA-5 (1) (b)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes service account must utilize certificates for authentication.'
    end
end