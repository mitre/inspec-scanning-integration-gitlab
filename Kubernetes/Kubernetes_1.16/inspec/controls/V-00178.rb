# encoding: UTF-8

control 'V-00178' do
    title 'The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.'
    desc  "Without the association of security attributes to information, there is no basis for the application to make security related access-control decisions.
	Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 
	These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. 
	One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in transmission. If the security attributes are lost when the data is being transmitted, there is the risk of a data compromise."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000314'
    tag gid: 'V-00178'
    tag rid: ''
    tag stig_id: 'SRG-APP-000314'
    tag fix_id: ''
    tag cci: ['CCI-002264']
    tag nist: ['AC-16 a']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Data security tags would be handled by user services deployed within the Kubernetes, but would not be performed by the Kubernetes itself.'
    end
end