# encoding: UTF-8

control 'V-92821' do
  title "The Apache web server must only accept client certificates issued by
DoD PKI or DoD-approved PKI Certification Authorities (CAs)."
  desc  "Non-DoD approved PKIs have not been evaluated to ensure that they have
security controls and identity vetting procedures in place that are sufficient
for DoD systems to rely on the identity asserted in the certificate. PKIs
lacking sufficient security controls and identity vetting procedures risk being
compromised and issuing certificates that enable adversaries to impersonate
legitimate users."
  desc  'rationale', ''
  desc  'check', "
    In a command line, run \"httpd -M | grep -i ssl_module\".

    If the \"ssl_module\" is not found, this is a finding.

    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Search for the \"SSLCACertificateFile\" directive:

    # cat /<path_to_file>/httpd.conf | grep -i \"SSLCACertificateFile\"

    Review the path of the \"SSLCACertificateFile\" directive.

    Review the contents of <'path of SSLCACertificateFile'>\\ca-bundle.crt.

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
  desc  'fix', "Configure the web server’s trust store to trust only
DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners)."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag gid: 'V-92821'
  tag rid: 'SV-102909r1_rule'
  tag stig_id: 'AS24-U2-000810'
  tag fix_id: 'F-99065r1_fix'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

  config_path = input('config_path')
  ssl_module = command("httpd -M | grep -i ssl_module")
  cert_location = apache_conf(config_path).params('SSLCACertificateFile')

  describe "Module ssl_module should be installed" do 
    subject { ssl_module.stdout.strip } 
    it {should_not cmp "" }
  end

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