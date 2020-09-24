# encoding: UTF-8

control 'V-00117' do
    title 'The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
    desc  "Lack of authentication and identification enables non-organizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system. 
	Non-organizational users include all information system users other than organizational users which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors and guest researchers). 
	Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000180'
    tag gid: 'V-00117'
    tag rid: ''
    tag stig_id: 'SRG-APP-000180'
    tag fix_id: ''
    tag cci: ['CCI-000804']
    tag nist: ['IA-8']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Identification of a specific account falls outside the Kubernetes scope.'
    end
end