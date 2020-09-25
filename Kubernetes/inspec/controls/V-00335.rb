# encoding: UTF-8

control 'V-00335' do
    title 'The network element, application, or operating system must use a High Assurance Commercial Solution for Classified (CSfC) cryptographic algorithm for remote access to a classified network.'
    desc  "Use of improperly configured or lower-assurance equipment and solutions could compromise high-value information.
	The National Security Agency/Central Security Service's (NSA/CSS) CSfC Program enables commercial products to be used in layered solutions to protect classified National Security Systems (NSS) data. Currently, Suite B cryptographic algorithms are specified by NIST and are used by NSA's Information Assurance Directorate in solutions approved for protecting classified and unclassified NSS. However, quantum resistant algorithms will be required for future Suite B implementations."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000625'
    tag gid: 'V-00335'
    tag rid: ''
    tag stig_id: 'SRG-APP-000625'
    tag fix_id: ''
    tag cci: ['CCI-002450']
    tag nist: ['SC-13']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: A Kubernetes installation would not contain classified information.  If containers that are being implemented that cause Kubernetes to be in a classified environment, when those containers are introduced, they would have to meet this requirement.'
    end
end