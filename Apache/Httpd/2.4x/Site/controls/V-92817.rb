# encoding: UTF-8

control 'V-92817' do
  title "Non-privileged accounts on the hosting system must only access Apache
web server security-relevant information and functions through a distinct
administrative account."
  desc  "By separating Apache web server security functions from non-privileged
users, roles can be developed that can then be used to administer the Apache
web server. Forcing users to change from a non-privileged account to a
privileged account when operating on the Apache web server or on
security-relevant information forces users to only operate as a Web Server
Administrator when necessary. Operating in this manner allows for better
logging of changes and better forensic information and limits accidental
changes to the Apache web server."
  desc  'rationale', ''
  desc  'check', "
    Determine which tool or control file is used to control the configuration
of the web server.

    If the control of the web server is done via control files, verify who has
update access to them. If tools are being used to configure the web server,
determine who has access to execute the tools.

    If accounts other than the System Administrator, Web Manager, or the Web
Manager designees have access to the web administration tool or control files,
this is a finding.
  "
  desc  'fix', "Restrict access to the web administration tool to only the
System Administrator, Web Manager, or the Web Manager designees."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000340-WSR-000029'
  tag gid: 'V-92817'
  tag rid: 'SV-102905r1_rule'
  tag stig_id: 'AS24-U2-000700'
  tag fix_id: 'F-99061r1_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  describe "Review access to the web administration tool" do 
    skip "If accounts other than the System Administrator (SA), the Web Manager, or the Web Manager designees have access to the 
    web administration tool or control files, this is a finding. Determine which tool or control file is used to control the 
    configuration of the web server. If the control of the web server is done via control files, verify who has update access to them. 
    If tools are being used to configure the web server, determine who has access to execute the tools."
  end
  
end

