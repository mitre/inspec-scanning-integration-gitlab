# encoding: UTF-8

control 'V-00088' do
    title 'The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
    desc  "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 
	Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.
	(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000148'
    tag gid: 'V-00088'
    tag rid: ''
    tag stig_id: 'SRG-APP-000148'
    tag fix_id: ''
    tag cci: ['CCI-000764']
    tag nist: ['IA-2']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: User authentication is performed by an external application defined by the organization.  Once authenticated, Kubernetes uses the authenticated user information to implement authorization to services.  Therefore, this requirement does not apply.'
    end
end