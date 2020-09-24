# encoding: UTF-8

control 'V-92727' do
  title "The Apache web server must prohibit or restrict the use of nonsecure
or unnecessary ports, protocols, modules, and/or services."
  desc  "Web servers provide numerous processes, features, and functionalities
that use TCP/IP ports. Some of these processes may be deemed unnecessary or too
unsecure to run on a production system.

    The Apache web server must provide the capability to disable or deactivate
network-related services that are deemed to be non-essential to the server
mission, are too unsecure, or are prohibited by the Ports, Protocols, and
Services Management (PPSM) Category Assurance List (CAL) and vulnerability
assessments.
  "
  desc  'rationale', ''
  desc  'check', "Review the website to determine if HTTP and HTTPs are used in
accordance with well known ports (e.g., 80 and 443) or those ports and services
as registered and approved for use by the DoD PPSM. Any variation in PPS will
be documented, registered, and approved by the PPSM. If not, this is a finding."
  desc  'fix', "Ensure the website enforces the use of IANA well-known ports
for HTTP and HTTPS."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: 'V-92727'
  tag rid: 'SV-102815r1_rule'
  tag stig_id: 'AS24-U1-000780'
  tag fix_id: 'F-98971r1_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe "Review the website to determine if HTTP and HTTPs are used in accordance with well known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD PPSM. Any variation in PPS will be documented, registered, and approved by the PPSM" do 
    skip "The Apache web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services. If not, this is a finding."
  end

end

