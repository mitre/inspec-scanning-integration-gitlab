# encoding: UTF-8

control 'V-00255' do
    title 'The application must maintain the confidentiality and integrity of information during preparation for transmission.'
    desc  "Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.
	This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.
	An example of this would be the SMTP queue. The SMTP mail protocol places email messages into a centralized queue prior to transmission. If someone were to modify an email message contained in the queue and the SMTP protocol did not check to ensure the email message was not modified while it was stored in the queue, a modified email could be sent."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact CHANGE_ME
    tag severity: 'CHANGE_ME'
    tag gtitle: 'SRG-APP-000441'
    tag gid: 'V-00255'
    tag rid: ''
    tag stig_id: 'SRG-APP-000441'
    tag fix_id: ''
    tag cci: ['CCI-002420']
    tag nist: ['SC-8 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Security control STIG Check and Fix is addressed in the following security controls: AC-17(2), AC-3, SC-23, SC-8.'
    end
end