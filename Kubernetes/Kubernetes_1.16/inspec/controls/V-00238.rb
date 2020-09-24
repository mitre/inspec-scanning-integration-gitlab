# encoding: UTF-8

control 'V-00238' do
    title 'The application must use a Commercial Solution for Classified (CSfC) when transporting classified traffic across an unclassified network.'
    desc  "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.
	The National Security Agency/Central Security Service's (NSA/CSS) Commercial Solutions for Classified (CSfC) Program enables commercial products to be used in layered solutions to protect classified NSS data. Currently, Suite B cryptographic algorithms are specified by the National Institute of Standards and Technology (NIST) and are used by NSA's Information Assurance Directorate in solutions approved for protecting classified and unclassified National Security Systems (NSS). However, quantum resistant algorithms will be required for future required Suite B implementations."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000416'
    tag gid: 'V-00238'
    tag rid: ''
    tag stig_id: 'SRG-APP-000416'
    tag fix_id: ''
    tag cci: ['CCI-002450']
    tag nist: ['SC-13']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Does not fall in scope for Kubernetes as the application is not responsible for implementing CSfc.  The approved vendors are responsibility  for implementing this control.'
    end
end