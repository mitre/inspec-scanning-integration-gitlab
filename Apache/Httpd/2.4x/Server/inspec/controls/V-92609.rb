# encoding: UTF-8

control 'V-92609' do
  title "The Apache web server must generate, at a minimum, log records for
system startup and shutdown, system access, and system authentication events."
  desc  "Log records can be generated from various components within the Apache
web server (e.g., httpd, plug-ins to external backends, etc.). From a web
server perspective, certain specific Apache web server functionalities may be
logged as well. The Apache web server must allow the definition of what events
are to be logged. As conditions change, the number and types of events to be
logged may change, and the Apache web server must be able to facilitate these
changes.

    The minimum list of logged events should be those pertaining to system
startup and shutdown, system access, and system authentication events. If these
events are not logged at a minimum, any type of forensic investigation would be
missing pertinent information needed to replay what occurred.


  "
  desc  'rationale', ''
  desc  'check', "
    In a command line, run \"httpd -M | grep -i log_config_module\".

    If the \"log_config_module\" is not enabled, this is a finding.

    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Search for the directive \"LogFormat\" in the \"httpd.conf\" file:

    # cat /<path_to_file>/httpd.conf | grep -i \"LogFormat\"

    If the \"LogFormat\" directive is missing, this is a finding:

    An example is:
    LogFormat \"%a %A %h %H %l %m %s %t %u %U \\\"%{Referer}i\\\" \" common

  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Uncomment the \"log_config_module\" module line.

    Configure the \"LogFormat\" in the \"httpd.conf\" file to look like the
following:

    LogFormat \"%a %A %h %H %l %m %s %t %u %U \\\"%{Referer}i\\\" \" common

    Restart Apache: apachectl restart

    NOTE: Your log format may be using different variables based on your
environment, however  it should be verified to be producing the same end result
of logged elements.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag satisfies: ['SRG-APP-000089-WSR-000047', 'SRG-APP-000092-WSR-000055',
'SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057',
'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059',
'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064']
  tag gid: 'V-92609'
  tag rid: 'SV-102697r2_rule'
  tag stig_id: 'AS24-U1-000070'
  tag fix_id: 'F-98851r1_fix'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133',
  'CCI-000134', 'CCI-000169', 'CCI-001464', 'CCI-001487']
  tag nist: ['AU-3', 'AU-3', 'AU-3', 'AU-3', 'AU-3', 'AU-12 a', 'AU-14 (1)',
  'AU-3']

  config_path = input('config_path')
  describe "LogFormat directive must be included in Apache config file" do
  subject { apache_conf(config_path).params.include? "LogFormat" }
    it { should cmp true }
  end

  describe "Module log_config_module should be installed" do 
  subject { command('httpd -M | grep -i log_config_module').stdout.strip }
    it { should_not cmp "" }
  end

end

