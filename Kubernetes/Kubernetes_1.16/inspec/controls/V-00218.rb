# encoding: UTF-8

control 'V-00218' do
    title 'The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.'
    desc  "Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.
	The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.
	Verification of whitelisted software can occur either prior to execution or at system startup.
	This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000386'
    tag gid: 'V-00218'
    tag rid: ''
    tag stig_id: 'SRG-APP-000386'
    tag fix_id: ''
    tag cci: ['CCI-001774']
    tag nist: ['CM-7 (5) (b)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: This requirement is for configuration management system.  Kubernetes is not a configuration management application, therefore this requirement is out of scope.'
    end
end