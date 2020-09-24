# encoding: UTF-8

control 'V-00180' do
    title 'The application must provide the capability to immediately disconnect or disable remote access to the information system.'
    desc  "Without the ability to immediately disconnect or disable remote access, an attack or other compromise taking progress would not be immediately stopped.
	Applications must have the capability to immediately disconnect current users remotely accessing the information system and/or disable further remote access. The speed of disconnect or disablement varies based on the criticality of missions/business functions and the need to eliminate immediate or future remote access to organizational information systems.
	The remote access application (e.g., VPN client) may implement features, such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000316'
    tag gid: 'V-00180'
    tag rid: ''
    tag stig_id: 'SRG-APP-000316'
    tag fix_id: ''
    tag cci: ['CCI-002322']
    tag nist: ['AC-17 (9)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Remote management is managed by harden Operating System and  Applications in addition to controls by network  devices and is outside the Kubernetes scope.'
    end
end