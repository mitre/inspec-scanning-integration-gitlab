# encoding: UTF-8

control 'V-92795' do
  title "Cookies exchanged between the Apache web server and client, such as
session cookies, must have security settings that disallow cookie access
outside the originating Apache web server and hosted application."
  desc  "Cookies are used to exchange data between the web server and the
client. Cookies, such as a session cookie, may contain session information and
user credentials used to maintain a persistent connection between the user and
the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path
parameters), cookies can be shared within hosted applications residing on the
same web server or to applications hosted on different web servers residing on
the same domain.
  "
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Search for the \"Header\" directive:

    # cat /<path_to_file>/httpd.conf | grep -i \"Header\"

    If \"HttpOnly\" \"secure\" is not configured, this is a finding.

    \"Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure\"

    Review the code. If, when creating cookies, the following is not occurring,
this is a finding:

    function setCookie() { document.cookie = \"ALEPH_SESSION_ID = $SESS; path =
/; secure\"; }
  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Add or configure the following line:

    \"Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure\"

    Add the \"secure\" attribute to the JavaScript set cookie in any
application code:

    function setCookie() { document.cookie = \"ALEPH_SESSION_ID = $SESS; path =
/; secure\"; }

    HttpOnly cannot be used since by definition this is a cookie set by
JavaScript.

    Restart www_server and Apache.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag gid: 'V-92795'
  tag rid: 'SV-102883r1_rule'
  tag stig_id: 'AS24-U2-000470'
  tag fix_id: 'F-99039r1_fix'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']

  config_path = input('config_path')
  headers = apache_conf(config_path).params("Header")

  if !headers.nil? 
    describe headers[0] do 
      it { should include "HttpOnly" }
      it { should include "secure" }
    end
  else
    describe "Headers directive could not be found" do 
      skip "Secure cookie settings must be defined in Header messages"
    end
  end

  describe "Review application code for proper use of setting cookies" do 
    skip "The JavaScript setCookies() function in application code must include the 'secure' parameter."
  end
  
end

