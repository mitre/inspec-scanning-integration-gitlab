# encoding: UTF-8

control 'V-92819' do
  title "The Apache web server application, libraries, and configuration files
must only be accessible to privileged users."
  desc  "The Apache web server can be modified through parameter modification,
patch installation, upgrades to the Apache web server or modules, and security
parameter changes. With each of these changes, there is the potential for an
adverse effect such as a denial of service (DoS), Apache web server
instability, or hosted application instability.

    To limit changes to the Apache web server and limit exposure to any adverse
effects from the changes, files such as the Apache web server application
files, libraries, and configuration files must have permissions and ownership
set properly to only allow privileged users access.
  "
  desc  'rationale', ''
  desc  'check', "
    Obtain a list of the user accounts for the system, noting the privileges
for each account.

    Verify with the System Administrator (SA) or the Information System
Security Officer (ISSO) that all privileged accounts are mission essential and
documented.

    Verify with the SA or the ISSO that all non-administrator access to shell
scripts and operating system functions are mission essential and documented.

    If undocumented privileged accounts are found, this is a finding.

    If undocumented access to shell scripts or operating system functions is
present, this is a finding.
  "
  desc  'fix', "Ensure non-administrators are not allowed access to the
directory tree, the shell, or other operating system functions and utilities."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag gid: 'V-92819'
  tag rid: 'SV-102907r1_rule'
  tag stig_id: 'AS24-U2-000780'
  tag fix_id: 'F-99063r1_fix'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  describe "The Apache web server application, libraries, and configuration files must only be accessible to privileged users." do 
    skip "Obtain a list of the user accounts for the system, noting the privileges for each account.
      Verify with the System Administrator (SA) or the Information System Security Officer (ISSO) that all privileged accounts are mission essential and documented. 
      Verify with the SA or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.
      If undocumented privileged accounts are found, this is a finding. 
      If undocumented access to shell scripts or operating system functions is present, this is a finding."
  end
  
end

