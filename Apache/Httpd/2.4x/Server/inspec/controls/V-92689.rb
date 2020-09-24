# encoding: UTF-8

control 'V-92689' do
  title "The Apache web server must generate a session ID using as much of the
character set as possible to reduce the risk of brute force."
  desc  "Generating a session identifier (ID) that is not easily guessed
through brute force is essential to deter several types of session attacks. By
knowing the session ID, an attacker can hijack a user session that has already
been user-authenticated by the hosted application. The attacker does not need
to guess user identifiers and passwords or have a secure token since the user
session has already been authenticated.

    By generating session IDs that contain as much of the character set as
possible, i.e., A-Z, a-z, and 0-9, the session ID becomes exponentially harder
to guess.


  "
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Verify the \"unique_id_module\" is loaded:

    run httpd -M | grep unique_id
    If no unique_id is returned, open finding.

  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Load the \"unique_id_module\".

    Example: LoadModule unique_id_module modules/mod_unique_id.so

    Restart Apache: apachectl restart
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000224-WSR-000138'
  tag satisfies: ['SRG-APP-000223-WSR-000145', 'SRG-APP-000224-WSR-000135',
'SRG-APP-000224-WSR-000136', 'SRG-APP-000224-WSR-000138']
  tag gid: 'V-92689'
  tag rid: 'SV-102777r2_rule'
  tag stig_id: 'AS24-U1-000520'
  tag fix_id: 'F-98931r2_fix'
  tag cci: ['CCI-001188', 'CCI-001664']
  tag nist: ['SC-23 (3)', 'SC-23 (3)']

  unique_id_module = command("httpd -M | grep unique_id").stdout

  describe unique_id_module do 
    it { should include "unique_id_module" }
  end 

end