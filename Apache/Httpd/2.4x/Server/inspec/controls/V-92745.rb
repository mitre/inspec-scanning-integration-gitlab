# encoding: UTF-8

control 'V-92745' do
  title "The Apache web server must remove all export ciphers to protect the
confidentiality and integrity of transmitted information."
  desc  "During the initial setup of a Transport Layer Security (TLS)
connection to the Apache web server, the client sends a list of supported
cipher suites in order of preference. The Apache web server will reply with the
cipher suite it will use for communication from the client list. If an attacker
can intercept the submission of cipher suites to the Apache web server and
place, as the preferred cipher suite, a weak export suite, the encryption used
for the session becomes easy for the attacker to break, often within minutes to
hours."
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Search for the \"SSLCACertificateFile\" directive:

    # cat /<path_to_file>/httpd.conf | grep -i \"SSLCACertificateFile\"

    Review the path of the \"SSLCACertificateFile\" directive.

    Review the contents of <'path of cert'>\\ca-bundle.crt.

    Examine the contents of this file to determine if the trusted CAs are DoD
approved.

    If the trusted CA that is used to authenticate users to the website does
not lead to an approved DoD CA, this is a finding.

    NOTE: There are non-DoD roots that must be on the server for it to
function. Some applications, such as antivirus programs, require root CAs to
function. DoD-approved certificate can include the External Certificate
Authorities (ECA) if approved by the AO. The PKE InstallRoot 3.06 System
Administrator Guide (SAG), dated 08 Jul 2008, contains a complete list of DoD,
ECA, and IECA CAs.
  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Ensure the \"SSLProtocol\" is added and looks like the following:

    SSLProtocol -ALL +TLSv1.2

    Restart Apache: apachectl restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag gid: 'V-92745'
  tag rid: 'SV-102833r1_rule'
  tag stig_id: 'AS24-U1-000900'
  tag fix_id: 'F-98989r1_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  config_path = input('config_path')
  cert_location = apache_conf(config_path).params('SSLCACertificateFile')

  if !cert_location.nil?
    describe "This is a manual check" do 
      skip "Examine the contents of the SSL CA Certificate file: #{cert_location.join(",")} If the trusted CAs are not DoD approved. This is a finding."
    end
  else
    describe "This is a manual check" do 
      skip "Unable to find the location SSLCACertificateFile directive. The server must use DoD Approved CAs for authentication" 
    end
  end

end