# encoding: UTF-8

control 'V-00158' do
    title 'The application that implements spam protection mechanisms must be updated automatically.'
    desc  "Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. A manual update procedure is labor intensive and does not scale well in an enterprise environment. This risk may be mitigated by using an automatic update capability. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000261'
    tag gid: 'V-00158'
    tag rid: ''
    tag stig_id: 'SRG-APP-000261'
    tag fix_id: ''
    tag cci: ['CCI-001308']
    tag nist: ['SI-8 (2)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: Spam protection does not fall under the scope of Kubernetes scope.'
    end
end