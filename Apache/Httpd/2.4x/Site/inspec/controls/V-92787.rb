# encoding: UTF-8

control 'V-92787' do
  title "Only authenticated system administrators or the designated PKI Sponsor
for the Apache web server must have access to the Apache web servers private
key."
  desc  "The web server's private key is used to prove the identity of the
server to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an
authorized server and decrypt the SSL traffic between a client and the web
server.
  "
  desc  'rationale', ''
  desc  'check', "
    In a command line, run \"httpd -M | grep -i ssl_module\".

    If the \"ssl_module\" is not enabled, this is a finding.

    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Review the private key path in the \"SSLCertificateFile\" directive. Verify
only authenticated system administrators and the designated PKI Sponsor for the
web server can access the web server private key.

    If the private key is accessible by unauthenticated or unauthorized users,
this is a finding.
  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Based on the \"SSLCertificateFile\" directive path, configure the Apache
web server to ensure only authenticated and authorized users can access the web
server's private key.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-92787'
  tag rid: 'SV-102875r1_rule'
  tag stig_id: 'AS24-U2-000390'
  tag fix_id: 'F-99031r1_fix'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  ssl_module = command("httpd -M | grep -i ssl_module").stdout

  describe ssl_module do 
    it {should include "ssl_module" }
  end

  describe "The private key should not be accessible by unauthenticated or unauthorized users" do 
    skip "Review the private key path in the \"SSLCertificateFile\" directive in Apache config file. 
      Verify only authenticated system administrators and the designated PKI Sponsor for the web server can access 
      the web server private key."
  end

end

