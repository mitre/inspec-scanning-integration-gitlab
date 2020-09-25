# encoding: UTF-8

control 'V-00179' do
    title 'The application must control remote access methods.'
    desc  "Remote access applications, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and makes remote user access management difficult at best.
	Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
	Remote access applications must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000315'
    tag gid: 'V-00179'
    tag rid: ''
    tag stig_id: 'SRG-APP-000315'
    tag fix_id: ''
    tag cci: ['CCI-002314']
    tag nist: ['AC-17 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Remote management is managed by harden Operating System and  Applications in addition to controls by network  devices and is outside the Kubernetes scope.'
    end
end