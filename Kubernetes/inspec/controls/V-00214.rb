# encoding: UTF-8

control 'V-00214' do
    title 'The application must enforce access restrictions associated with changes to application configuration.'
    desc  "Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. 
	When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 
	Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications. 
	Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000380'
    tag gid: 'V-00214'
    tag rid: ''
    tag stig_id: 'SRG-APP-000380'
    tag fix_id: ''
    tag cci: ['CCI-001813']
    tag nist: ['CM-5 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: The configuration of Kubernetes is stored on the host filesystem.  Enforcement of authorization would be performed by the host system OS.'
    end
end