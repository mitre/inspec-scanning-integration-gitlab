# encoding: UTF-8

control 'V-92815' do
  title "The Apache web server must restrict inbound connections from nonsecure
zones."
  desc  "Remote access to the Apache web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    A web server can be accessed remotely and must be capable of restricting
access from what the DoD defines as nonsecure zones. Nonsecure zones are
defined as any IP, subnet, or region that is defined as a threat to the
organization. The nonsecure zones must be defined for public web servers
logically located in a DMZ, as well as private web servers with perimeter
protection devices. By restricting access from nonsecure zones, through the
internal web server access list, the Apache web server can stop or slow
denial-of-service (DoS) attacks on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    If external controls such as host-based firewalls are used to restrict this
access, this check is Not Applicable.

    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Search for the \"RequireAll\" directive:

    # cat /<path_to_file>/httpd.conf | grep -i \"RequireAll\"

    If \"RequireAll\" is not configured or IP ranges configured to allow are
not restrictive enough to prevent connections from nonsecure zones, this is a
finding.
  "
  desc  'fix', "
    Configure the \"http.conf\" file to include restrictions.

    Example:

    <RequireAll>
    Require not ip 192.168.205
    Require not host phishers.example.com
    </RequireAll>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag gid: 'V-92815'
  tag rid: 'SV-102903r1_rule'
  tag stig_id: 'AS24-U2-000680'
  tag fix_id: 'F-99059r2_fix'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']

  describe "If external controls such as host-based firewalls are used to restrict this access, this check is Not Applicable." do 
    skip "Search for the \"RequireAll\" directive. If \"RequireAll\" is not configured or IP ranges configured to allow are not restrictive enough to prevent connections from nonsecure zones, this is a finding."
  end
  
end

