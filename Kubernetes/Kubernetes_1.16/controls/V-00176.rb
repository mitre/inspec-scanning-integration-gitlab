# encoding: UTF-8

control 'V-00176' do
    title 'The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.'
    desc  "Without the association of security attributes to information, there is no basis for the application to make security related access-control decisions.
	Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 
	These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. 
	One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in storage. If the security attributes are lost when the data is stored, there is the risk of a data compromise."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000311'
    tag gid: 'V-00176'
    tag rid: ''
    tag stig_id: 'SRG-APP-000311'
    tag fix_id: ''
    tag cci: ['CCI-002262']
    tag nist: ['AC-16 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Storage management is outside the Kuberenetes scope.'
    end
end