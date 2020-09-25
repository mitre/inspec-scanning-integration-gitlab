# encoding: UTF-8

control 'V-00053' do
    title 'The application must provide the capability for authorized users to capture, record, and log all content related to a user session.'
    desc  "Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered. 
	This requirement does not apply to applications that do not have a concept of a user session (e.g., calculator)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000093'
    tag gid: 'V-00053'
    tag rid: ''
    tag stig_id: 'SRG-APP-000093'
    tag fix_id: ''
    tag cci: ['CCI-001462']
    tag nist: ['AU-14 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Logging of user sessions to Kubernetes is addressed in other requirments.  Logging of sessions to containers offering user services would be done by the user service itself, not Kubernetes.'
    end
end