# encoding: UTF-8

control 'V-92643' do
  title 'The Apache web server must not be a proxy server.'
  desc  "A web server should be primarily a web server or a proxy server but
not both, for the same reasons that other multi-use servers are not
recommended. Scanning for web servers that will also proxy requests into an
otherwise protected network is a very common attack, making the attack
anonymous."
  desc  'rationale', ''
  desc  'check', "
    If the server is a proxy server and not a web server, this check is Not
Applicable.

    In a command line, run \"httpd -M | sort\" to view a list of installed
modules.

    If any of the following modules are present, this is a finding:

    proxy_module
    proxy_ajp_module
    proxy_balancer_module
    proxy_ftp_module
    proxy_http_module
    proxy_connect_module
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:
    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Search for the directive \"ProxyRequest\" in the \"httpd.conf\" file.
    If the ProxyRequest directive is set to “On”, this is a finding.

  "
  desc  'fix', "
    Determine where the proxy modules are located by running the following
command:

    grep -rl \"proxy_module\" <'INSTALL PATH'>

    Edit the file and comment out the following modules:

    proxy_module
    proxy_ajp_module
    proxy_balancer_module
    proxy_ftp_module
    proxy_http_module
    proxy_connect_module
    Comment out the ProxyRequext directive in the httpd.conf file.

    Restart Apache: apachectl restart

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag gid: 'V-92643'
  tag rid: 'SV-102731r2_rule'
  tag stig_id: 'AS24-U1-000260'
  tag fix_id: 'F-98885r2_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  config_path = input('config_path')
  modules_command = "httpd -M | sort"
  installed_modules = command(modules_command).stdout.split 
  
  check_modules = [
    "proxy_module",
    "proxy_ajp_module",
    "proxy_balancer_module",
    "proxy_ftp_module",
    "proxy_http_module",
    "proxy_connect_module"
  ]

  bad_modules = installed_modules.select do |i|
    check_modules.any? {|j| i.include?(j) }
  end

  describe "The following modules should be removed from Apache server" do
    skip "The following modules should be removed: #{bad_modules.join(', ')}"  
  end

  if !apache_conf(config_path).params("ProxyRequest").nil?
    describe apache_conf(config_path) do 
      its("ProxyRequest") { should_not cmp "On" }
    end
  else
    describe "ProxyRequest directive should not be set to On" do 
      skip "ProxyRequest is not defined in Apache Config. Skipping this check"
    end
  end

end