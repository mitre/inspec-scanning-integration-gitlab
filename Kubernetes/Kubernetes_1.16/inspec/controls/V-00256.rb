# encoding: UTF-8

control 'V-00256' do
    title 'The application must maintain the confidentiality and integrity of information during reception.'
    desc  "Information can be either unintentionally or maliciously disclosed or modified during reception including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.
	This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When receiving data, applications need to leverage protection mechanisms, such as TLS, TLS VPNs, or IPSEC."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact CHANGE_ME
    tag severity: 'CHANGE_ME'
    tag gtitle: 'SRG-APP-000442'
    tag gid: 'V-00256'
    tag rid: ''
    tag stig_id: 'SRG-APP-000442'
    tag fix_id: ''
    tag cci: ['CCI-002422']
    tag nist: ['SC-8 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Security control STIG Check and Fix is addressed in the following security controls: AC-17(2), AC-3, SC-23, SC-8.'
    end
end