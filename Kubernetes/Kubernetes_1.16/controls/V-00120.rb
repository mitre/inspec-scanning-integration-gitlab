# encoding: UTF-8

control 'V-00120' do
    title 'The application must terminate all sessions and network connections when non-local maintenance is completed.'
    desc  "If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.
	Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. 
	This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing \"ping,\" \"ls,\" \"ipconfig,\" or the hardware and software implementing the monitoring port of an Ethernet switch)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000186'
    tag gid: 'V-00120'
    tag rid: ''
    tag stig_id: 'SRG-APP-000186'
    tag fix_id: ''
    tag cci: ['CCI-000879']
    tag nist: ['MA-4 e']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Network endpoints, gateways, load balancers with regards to session management  fall outside the scope of Kubernetes scope.'
    end
end