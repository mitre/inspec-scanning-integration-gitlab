# encoding: UTF-8

control 'V-00219' do
    title 'The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.'
    desc  "Without reauthentication, users may access resources or perform tasks for which they do not have authorization. 
	When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user reauthenticate.
	In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances.
	(i) When authenticators change; 
    (ii) When roles change; 
    (iii) When security categories of information systems change; 
    (iv) When the execution of privileged functions occurs; 
    (v) After a fixed period of time; or
    (vi) Periodically.
	Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000389'
    tag gid: 'V-00219'
    tag rid: ''
    tag stig_id: 'SRG-APP-000389'
    tag fix_id: ''
    tag cci: ['CCI-002038']
    tag nist: ['IA-11']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Authentication of users is handled by organization defined external resources which would handle reauthentication.  Kubernetes then uses the authenticated user to determine authorization of services.'
    end
end