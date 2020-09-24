# encoding: UTF-8

control 'V-92705' do
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
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Verify the \"reqtimeout_module\" is loaded:

    # cat /<path_to_file>/httpd.conf | grep -i \"reqtimeout_module\"

    If the \"reqtimeout_module\" is not loaded, this is a finding.

    Verify the \"RequestReadTimeout\" directive is configured.

    If the \"reqtimeout_module\" is loaded and the \"RequestReadTimeout\"
directive is not configured, this is a finding.
  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Load the \"reqtimeout_module\".

    Set the \"RequestReadTimeout\" directive.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag gid: 'V-92705'
  tag rid: 'SV-102793r1_rule'
  tag stig_id: 'AS24-U1-000650'
  tag fix_id: 'F-98947r1_fix'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  config_path = input('config_path')
  req_timeout = command("httpd -M | grep reqtimeout_module").stdout.strip

  describe req_timeout do 
    it { should include "reqtimeout_module" }
  end 

  describe apache_conf(config_path) do 
    its("RequestReadTimeout") { should_not cmp "" }
  end
  
end