# encoding: UTF-8

control 'V-00098' do
    title 'The application must uniquely identify all network connected endpoint devices before establishing any connection.'
    desc  "Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.
	For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.
	This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including but not limited to: workstations, printers, servers (outside a datacenter), VoIP Phones, VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000158'
    tag gid: 'V-00098'
    tag rid: ''
    tag stig_id: 'SRG-APP-000158'
    tag fix_id: ''
    tag cci: ['CCI-000778']
    tag nist: ['IA-3']

    describe 'This check is Not Applicable.' do
        skip 'Network management is outside the Kubernetes STIG scope.'
    end
end