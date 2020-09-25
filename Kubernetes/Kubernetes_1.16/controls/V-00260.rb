# encoding: UTF-8

control 'V-00260' do
    title 'The application must remove organization-defined firmware components after updated versions have been installed.'
    desc  "Previous versions of firmware components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of firmware automatically from the information system."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000455'
    tag gid: 'V-00260'
    tag rid: ''
    tag stig_id: 'SRG-APP-000455'
    tag fix_id: ''
    tag cci: ['CCI-002618']
    tag nist: ['SI-2 (6)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: Hardware maintenance falls outside the Kubernetes scope.'
    end
end