# encoding: UTF-8

control 'V-00150' do
    title 'The application must use FIPS-validated encryption and hashing algorithms to protect the confidentiality and integrity of application configuration files and user-generated data stored or aggregated on the device.'
    desc  "Confidentiality and integrity protections are intended to address the confidentiality and integrity of system information at rest (e.g., network device rule sets) when it is located on a storage device within the network device or as a component of the network device. This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.
	This requirement addresses protection of user-generated data as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000231'
    tag gid: 'V-00150'
    tag rid: ''
    tag stig_id: 'SRG-APP-000231'
    tag fix_id: ''
    tag cci: ['CCI-001199']
    tag nist: ['SC-28']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: The configuration files are stored on the host system filesystem.  The use FIPS-validated encryption and hashing algorithms to protect the confidentiality and integrity of these files would be a requirement of the hosting system.'
    end
end