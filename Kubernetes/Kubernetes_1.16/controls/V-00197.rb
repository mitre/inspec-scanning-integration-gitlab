# encoding: UTF-8

control 'V-00197' do
  title 'The application must provide an immediate warning to the SA and IAO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc  "If security personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion."
  desc  'rationale', ''
  desc  'check', ""
  desc  'fix', ""
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000359'
  tag gid: 'V-00197'
  tag rid: ''
  tag stig_id: 'SRG-APP-000359'
  tag fix_id: ''
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe 'This check is Not Applicable.' do
    skip 'Not Applicable: Central Storage is outside the Kubernetes scope.'
  end
end