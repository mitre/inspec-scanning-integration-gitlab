# encoding: UTF-8

control 'V-00330' do
    title 'If a cipher suite using pre-shared keys is used for device authentication of the application, the cipher suite must only be used in networks where both the client and server are Government systems.'
    desc  "Pre-shared keys are symmetric keys that are already in place prior to the initiation of a Transport Layer Security (TLS) session (e.g., as the result of a manual distribution). In general, pre-shared keys should not be used. However, the use of pre-shared keys may be appropriate for some closed environments that have adequate key management support.  There are known vulnerabilities with using pre-shared keys with TLS 1.0 or earlier versions of SSL."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000590'
    tag gid: 'V-00330'
    tag rid: ''
    tag stig_id: 'SRG-APP-000590'
    tag fix_id: ''
    tag cci: ['CCI-001967']
    tag nist: ['IA-3 (1)']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: Preshare keys falls out of the Kubernetes scope.'
    end
end