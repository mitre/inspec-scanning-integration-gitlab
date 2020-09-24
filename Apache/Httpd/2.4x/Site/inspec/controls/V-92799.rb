# encoding: UTF-8

control 'V-92799' do
  title "The Apache web server document directory must be in a separate
partition from the Apache web servers system files."
  desc  "A web server is used to deliver content on the request of a client.
The content delivered to a client must be controlled, allowing only hosted
application files to be accessed and delivered. To allow a client access to
system files of any type is a major security risk that is entirely avoidable.
Obtaining such access is the goal of directory traversal and URL manipulation
vulnerabilities. To facilitate such access by misconfiguring the web document
(home) directory is a serious error. In addition, having the path on the same
drive as the system folder compounds potential attacks such as drive space
exhaustion."
  desc  'rationale', ''
  desc  'check', "
    Run the following command:

    grep \"DocumentRoot\"<'INSTALL PATH'>/conf/httpd.conf

    Note each location following the \"DocumentRoot\" string. This is the
configured path to the document root directory(s).

    Use the command df -k to view each document root's partition setup.

    Compare that against the results for the operating system file systems and
against the partition for the web server system files, which is the result of
the command:

    df -k <'INSTALL PATH'>/bin

    If the document root path is on the same partition as the web server system
files or the operating system file systems, this is a finding.
  "
  desc  'fix', "Move the web document (normally \"htdocs\") directory to a
separate partition other than the operating system root partition and the web
server’s system files."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000233-WSR-000146'
  tag gid: 'V-92799'
  tag rid: 'SV-102887r1_rule'
  tag stig_id: 'AS24-U2-000580'
  tag fix_id: 'F-99043r1_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  config_path = input('config_path')
  doc_mounts = Array.new()
  document_root = apache_conf(config_path).params("DocumentRoot")

  document_root.each do |docs|
    doc_mounts.push(command("df -k #{docs}").stdout.strip.split(" ")[-1])
  end 

  describe "Apache web server document directory must be in a separate partition from the Apache web servers system files." do 
    skip "The document directories were found on #{doc_mounts.join(", ")}. 
      If the document root path is on the same partition as the web server system files or the operating system file systems, this is a finding."

  end

end
