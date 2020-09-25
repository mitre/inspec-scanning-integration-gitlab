# encoding: UTF-8

control 'V-00237' do
    title 'The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
    desc  "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000416'
    tag gid: 'V-00237'
    tag rid: ''
    tag stig_id: 'SRG-APP-000416'
    tag fix_id: ''
    tag cci: ['CCI-002450']
    tag nist: ['SC-13']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: The Kubernetes cluster does not operate on classified information.  The information is only configuration information.  Once user services are installed, those services need to address the protection of the data they operate on.'
    end
end