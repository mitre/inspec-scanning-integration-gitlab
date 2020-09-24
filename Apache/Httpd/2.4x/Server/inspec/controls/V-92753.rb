# encoding: UTF-8

control 'V-92753' do
  title "The Apache web server must be configured in accordance with the
security configuration settings based on DoD security configuration or
implementation guidance, including STIGs, NSA configuration guides, CTOs, and
DTMs."
  desc  "Configuring the Apache web server to implement organization-wide
security implementation guides and security checklists guarantees compliance
with federal standards and establishes a common security baseline across the
DoD that reflects the most restrictive security posture consistent with
operational requirements.

    Configuration settings are the set of parameters that can be changed that
affect the security posture and/or functionality of the system.
Security-related parameters are parameters impacting the security state of the
Apache web server, including those required to satisfy other security control
requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the website to determine if \"HTTP\" and \"HTTPS\" are used in
accordance with well-known ports (e.g., 80 and 443) or those ports and services
as registered and approved for use by the DoD Ports, Protocols, and Services
Management (PPSM).

    Verify that any variation in PPS is documented, registered, and approved by
the PPSM.

    If well-known ports and services are not approved for used by PPSM, this is
a finding.
  "
  desc  'fix', "Ensure the website enforces the use of IANA well-known ports
for \"HTTP\" and \"HTTPS\"."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-92753'
  tag rid: 'SV-102841r1_rule'
  tag stig_id: 'AS24-U1-000950'
  tag fix_id: 'F-98997r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe "Ensure the website enforces the use of IANA well-known ports for HTTP and HTTPS." do 
    skip "Review the website to determine if \"HTTP\" and \"HTTPS\" are used in accordance 
      with well-known ports (e.g., 80 and 443) or those ports and services as registered and approved 
      for use by the DoD Ports, Protocols, and Services Management (PPSM).
      Verify that any variation in PPS is documented, registered, and approved by the PPSM.
      If well-known ports and services are not approved for used by PPSM, this is a finding."
  end
  
end

