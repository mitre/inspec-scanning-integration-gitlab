# encoding: UTF-8

control 'V-00210' do
    title 'The application must alert the IAO, IAM, and other designated personnel (deemed appropriate by the local organization) when the unauthorized installation of software is detected.'
    desc  "Unauthorized software not only increases risk by increasing the number of potential vulnerabilities, it also can contain malicious code. Sending an alert (in real time) when unauthorized software is detected allows designated personnel to take action on the installation of unauthorized software.
	This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000377'
    tag gid: 'V-00210'
    tag rid: ''
    tag stig_id: 'SRG-APP-000377'
    tag fix_id: ''
    tag cci: ['CCI-001811']
    tag nist: ['CM-11 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Software detection is outside the Kubernetes scope.'
    end
end