# encoding: UTF-8

control 'V-92811' do
  title 'The Apache web server must set an inactive timeout for sessions.'
  desc  "Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after a
set period of inactivity, the Apache web server can make certain that those
sessions that are not closed through the user logging out of an application are
eventually closed.

    Acceptable values are 5 minutes for high-value applications, 10 minutes for
medium-value applications, and 20 minutes for low-value applications.
  "
  desc  'rationale', ''
  desc  'check', "
    In a command line, run \"httpd -M | grep -i Reqtimeout_module\".

    If the \"Reqtimeout_module\" is not enabled, this is a finding.
  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Load the \"Reqtimeout_module\".

    Set the \"RequestReadTimeout\" directive.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag gid: 'V-92811'
  tag rid: 'SV-102899r1_rule'
  tag stig_id: 'AS24-U2-000660'
  tag fix_id: 'F-99055r1_fix'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  req_timeout_module = command("httpd -M | grep -i reqtimeout_module").stdout 

  describe req_timeout_module do 
    it { should include "reqtimeout_module" }
  end
  
end

