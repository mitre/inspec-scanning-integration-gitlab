# encoding: UTF-8

control 'V-00075' do
    title 'The application must prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
    desc  "Changes to any software components can have significant effects on the overall security of the application. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and that it has been provided by a trusted vendor. 
	Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization. 
	Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by This requirement. The application should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000131'
    tag gid: 'V-00075'
    tag rid: ''
    tag stig_id: 'SRG-APP-000131'
    tag fix_id: ''
    tag cci: ['CCI-001749']
    tag nist: ['CM-5 (3)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Kubernetes can be setup to verify digitally signed images before execution, but this can only be done with the installation of services that are outside the scope of this STIG and implementing a policy to enforce the rule of only executing signed images.  Since the digital signature store and register can be one of multiple choices, it would be difficult to even give a check and fix if within scope.'
    end
end