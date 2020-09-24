# encoding: UTF-8

control 'V-92801' do
  title "The Apache web server must be tuned to handle the operational
requirements of the hosted application."
  desc  "A denial of service (DoS) can occur when the Apache web server is so
overwhelmed that it can no longer respond to additional requests. A web server
not properly tuned may become overwhelmed and cause a DoS condition even with
expected traffic from users. To avoid a DoS, the Apache web server must be
tuned to handle the expected traffic for the hosted applications.


  "
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Verify that the \"Timeout\" directive is specified to have a value of
\"10\" seconds or less.

    # cat /<path_to_file>/httpd.conf | grep -i \"Timeout\"

    If the \"Timeout\" directive is not configured or is set for more than
\"10\" seconds, this is a finding.
  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Add or modify the \"Timeout\" directive in the Apache configuration to have
a value of \"10\" seconds or less.

    \"Timeout 10\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag satisfies: ['SRG-APP-000246-WSR-000149', 'SRG-APP-000435-WSR-000148']
  tag gid: 'V-92801'
  tag rid: 'SV-102889r1_rule'
  tag stig_id: 'AS24-U2-000590'
  tag fix_id: 'F-99045r1_fix'
  tag cci: ['CCI-001094', 'CCI-002385']
  tag nist: ['SC-5 (1)', 'SC-5']

  config_path = input('config_path')
  describe apache_conf(config_path) do 
    its("Timeout") { should cmp 10 }
  end
  
end

