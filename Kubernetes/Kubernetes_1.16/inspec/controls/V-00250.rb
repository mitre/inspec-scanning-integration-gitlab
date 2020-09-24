# encoding: UTF-8

control 'V-00250' do
    title 'The application must identify and log internal users associated with denied outgoing communications traffic posing a threat to external information systems.'
    desc  "Without identifying the users who initiated the traffic, it would be difficult to identify those responsible for the denied communications. This requirement applies to those applications that perform Data Leakage Prevention (DLP)/Extrusion Detection (ED)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000438'
    tag gid: 'V-00250'
    tag rid: ''
    tag stig_id: 'SRG-APP-000438'
    tag fix_id: ''
    tag cci: ['CCI-002400']
    tag nist: ['SC-7 (9) (b)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: Data leak prevention and detection services is outside the Kubernetes scope.'
    end
end