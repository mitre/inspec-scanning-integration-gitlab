# encoding: UTF-8

control 'V-92687' do
  title "The Apache web server must generate a session ID long enough that it
cannot be guessed through brute force."
  desc  "Generating a session identifier (ID) that is not easily guessed
through brute force is essential to deter several types of session attacks. By
knowing the session ID, an attacker can hijack a user session that has already
been user authenticated by the hosted application. The attacker does not need
to guess user identifiers and passwords or have a secure token since the user
session has already been authenticated.

    Generating session IDs that are at least 128 bits (16 bytes) in length will
cause an attacker to take a large amount of time and resources to guess,
reducing the likelihood of an attacker guessing a session ID.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the web server documentation and deployed configuration to determine
the length of the generated session identifiers.

    First ensure that \"session_crypto\" is enabled:

    httpd -M |grep session_crypto

    If the above command returns \"session_crypto_module\", the module is
enabled in the running server.

    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Review the \"httpd.conf\" file.

    If the \"SessionCryptoCipher\" is not used or \"SessionCryptoCipher\" is
not set to \"aes256\", this is a finding.
  "
  desc  'fix', "
    Configure the web server to generate session identifiers that are at least
128 bits in length.

    Ensure that \"session_crypto_module\" is enabled.

    Determine the location of the \"httpd.conf\" file by running the following
command:

    httpd -V

    Review the \"HTTPD_ROOT\" path.

    Navigate to the \"HTTPD_ROOT\"/conf directory.

    Edit the \"httpd.conf\" file.

    SessionCryptoCipher aes256

    Restart Apache: apachectl restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000224-WSR-000137'
  tag gid: 'V-92687'
  tag rid: 'SV-102775r1_rule'
  tag stig_id: 'AS24-U1-000510'
  tag fix_id: 'F-98929r1_fix'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']

  config_path = input('config_path')
  session_crypto = command("httpd -M | grep session_crypto").stdout

  describe session_crypto do 
    it { should include "session_crypto_module" }
  end

  describe apache_conf(config_path) do 
    its("SessionCryptoCipher") { should cmp "aes256" }
  end 

end