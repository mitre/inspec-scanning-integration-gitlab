# encoding: UTF-8

control 'V-00223' do
    title 'The application must authenticate all network connected endpoint devices before establishing any connection.'
    desc  "Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.
	For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.
	This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including but not limited to: workstations, printers, servers (outside a datacenter), VoIP Phones, VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply. 
	Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000394'
    tag gid: 'V-00223'
    tag rid: ''
    tag stig_id: 'SRG-APP-000394'
    tag fix_id: ''
    tag cci: ['CCI-001958']
    tag nist: ['IA-3']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Endpoint management falls outside the Kubernetes scope.'
    end
end