# encoding: UTF-8

control 'V-00070' do
    title 'The application must protect audit tools from unauthorized access.'
    desc  "Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.
	Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.
	Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000121'
    tag gid: 'V-00070'
    tag rid: ''
    tag stig_id: 'SRG-APP-000121'
    tag fix_id: ''
    tag cci: ['CCI-001493']
    tag nist: ['AU-9']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Audit information will be stored outside the Kubernetes Control Plane scope.'
    end
end