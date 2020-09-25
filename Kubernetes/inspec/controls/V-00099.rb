# encoding: UTF-8

control 'V-00099' do
    title 'The application must disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
    desc  "Inactive identifiers pose a risk to systems and applications. Attackers that are able to exploit an inactive identifier can potentially obtain and maintain undetected access to the application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. 
	Applications need to track periods of inactivity and disable application identifiers after 35 days of inactivity. 
	Management of user identifiers is not applicable to shared information system accounts (e.g., guest and anonymous accounts). It is commonly the case that a user account is the name of an information system account associated with an individual.
	To avoid having to build complex user management capabilities directly into their application, wise developers leverage the underlying OS or other user account management infrastructure (AD, LDAP) that is already in place within the organization and meets organizational user account management requirements."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000163'
    tag gid: 'V-00099'
    tag rid: ''
    tag stig_id: 'SRG-APP-000163'
    tag fix_id: ''
    tag cci: ['CCI-000795']
    tag nist: ['IA-4 e']

    describe 'This check is Not Applicable.' do
        skip 'Kubernetes service account must utilize certificates for authentication.'
    end
end