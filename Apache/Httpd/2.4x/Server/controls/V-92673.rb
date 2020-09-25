# encoding: UTF-8

control 'V-92673' do
  title "Apache web server application directories,  libraries, and
configuration files must only be accessible to privileged users."
  desc  "To properly monitor the changes to the web server and the hosted
applications, logging must be enabled. Along with logging being enabled, each
record must properly contain the changes made and the names of those who made
the changes.

    Allowing anonymous users the capability to change the web server or the
hosted application will not generate proper log information that can then be
used for forensic reporting in the case of a security issue. Allowing anonymous
users to make changes will also grant change capabilities to anybody without
forcing a user to authenticate before the changes can be made.


  "
  desc  'rationale', ''
  desc  'check', "
    Obtain a list of the user accounts for the system, noting the privileges
for each account.

    Verify with the SA or the Information System Security Officer (ISSO) that
all privileged accounts are mission essential and documented.

    Verify with the SA or the ISSO that all non-administrator access to shell
scripts and operating system functions are mission essential and documented.

    If undocumented privileged accounts are present, this is a finding.

    If undocumented access to shell scripts or operating system functions is
present, this is a finding.
  "
  desc  'fix', "Ensure non-administrators are not allowed access to the
directory tree, the shell, or other operating system functions and utilities."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag satisfies: ['SRG-APP-000211-WSR-000031', 'SRG-APP-000141-WSR-000078',
'SRG-APP-000380-WSR-000072']
  tag gid: 'V-92673'
  tag rid: 'SV-102761r1_rule'
  tag stig_id: 'AS24-U1-000440'
  tag fix_id: 'F-98915r1_fix'
  tag cci: ['CCI-000381', 'CCI-001082', 'CCI-001813']
  tag nist: ['CM-7 a', 'SC-2', 'CM-5 (1)']

  describe "Obtain a list of the user accounts for the system, noting the privileges for each account" do 
    skip "Verify with the SA or the Information System Security Officer (ISSO) that all privileged accounts are mission essential and documented.
      Verify with the SA or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.
      If undocumented privileged accounts are present, this is a finding.
      If undocumented access to shell scripts or operating system functions is present, this is a finding."
  end

end

