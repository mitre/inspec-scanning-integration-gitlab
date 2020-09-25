# encoding: UTF-8

control 'V-92759' do
  title 'HTTP request methods must be limited.'
  desc  "The HTTP 1.1 protocol supports several request methods that are rarely
used and potentially high risk. For example, methods such as PUT and DELETE are
rarely used and should be disabled in keeping with the primary security
principal of minimize features and options. Also, since the usage of these
methods is typically to modify resources on the web server, they should be
explicitly disallowed. Normal web server operation will typically require
allowing only the GET, HEAD, and POST request methods. This will allow for
downloading of web pages and submitting information to web forms. The OPTIONS
request method will also be allowed as it is used to request which HTTP request
methods are allowed."
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Enter the following command into a command line:

    more <'INSTALLED PATH'>/conf/httpd.conf

    For every enabled \"Directory\" directive (except root), verify the
following entry exists:

    <LimitExcept GET POST OPTIONS>
    Require all denied
    </LimitExcept>

    If the statement above is not found in the \"LimitExcept\" statement (i.e.,
<Directory />), this is a finding.

    If the statement above is found enabled but without the appropriate
\"LimitExcept\" or \"Order\" statement, this is a finding.

    If the statement is not found inside an enabled \"Directory\" directive,
this is a finding.

    NOTE: If the \"LimitExcept\" statement above is operationally limiting,
this should be explicitly documented and approved by the ISSO, at which point
this can be considered not a finding.

  "
  desc  'fix', "
    Edit the \"httpd.conf\" file and add the following entries for every
enabled \"Directory\" directive (except root).

    <LimitExcept GET POST OPTIONS>
    Require all denied
    </LimitExcept>

    Example:

    <Directory \"/usr/local/apache2/cgi-bin\">
    . . .
    # Limit HTTP methods
    <LimitExcept GET POST OPTIONS>
    Require all denied
    </LimitExcept>
    </Directory>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000093-WSR-000053'
  tag gid: 'V-92759'
  tag rid: 'SV-102847r2_rule'
  tag stig_id: 'AS24-U1-001000'
  tag fix_id: 'F-99003r1_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe directories_command do 
    skip "Check that each Directory directive has a LimitExcept defined"
  end

end



