# encoding: UTF-8

control 'V-00012' do
    title 'The application must monitor remote access methods.'
    desc  "Remote access applications, such as those providing remote access to network devices and information systems, which lack automated capabilities, increase risk and makes remote user access management difficult at best.
	Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
	Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access applications, such as VPN clients
    on a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000016'
    tag gid: 'V-00012'
    tag rid: ''
    tag stig_id: 'SRG-APP-000016'
    tag fix_id: ''
    tag cci: ['CCI-000067']
    tag nist: ['AC-17 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Remote monitoring falls outside Kubernetes scope.'
    end
end