# encoding: UTF-8

control 'V-00220' do
    title 'The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.'
    desc  "Without reauthenticating devices, unidentified or unknown devices may be introduced; thereby facilitating malicious activity.
	In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of devices, including (but not limited to), the following other situations.
	(i) When authenticators change; 
    (ii) When roles change; 
    (iii) When security categories of information systems change;
    (iv) After a fixed period of time; or 
    (v) Periodically.
	For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.
	Gateways and SOA applications are examples of where this requirement would apply."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000390'
    tag gid: 'V-00220'
    tag rid: ''
    tag stig_id: 'SRG-APP-000390'
    tag fix_id: ''
    tag cci: ['CCI-002039']
    tag nist: ['IA-11']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Authentication of devices is handled by organization defined external resources which would handle reauthentication. Kubernetes then uses the authenticated device to determine authorization of services.'
    end
end