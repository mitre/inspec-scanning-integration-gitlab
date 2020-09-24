# encoding: UTF-8

control 'V-92629' do
  title "The Apache web server log files must only be accessible by privileged
users."
  desc  "Log data is essential in the investigation of events. If log data were
to become compromised, competent forensic analysis and discovery of the true
source of potentially malicious system activity would be difficult, if not
impossible, to achieve. In addition, access to log records provides information
an attacker could potentially use to their advantage since each event record
might contain communication ports, protocols, services, trust relationships,
user names, etc.

    The web server must protect the log data from unauthorized read, write,
copy, etc. This can be done by the web server if the web server is also doing
the logging function. The web server may also use an external log system. In
either case, the logs must be protected from access by non-privileged users.
  "
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Review the log file location.

    To determine permissions for log files, from the command line, navigate to
the directory where the log files are located and enter the following command:

    ls -alH <HTTPD_ROOT>/log*

    Note the owner and group permissions on these files. Only system
administrators and service accounts running the server should have permissions
to the files.

    If any users other than those authorized have read access to the log files,
this is a finding.

  "
  desc  'fix', "To protect the integrity of the data that is being captured in
the log files, ensure that only the members of the Auditors group,
Administrators, and the user assigned to run the web server software is granted
permissions to read the log files."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag gid: 'V-92629'
  tag rid: 'SV-102717r2_rule'
  tag stig_id: 'AS24-U1-000180'
  tag fix_id: 'F-98871r1_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9']

  config_path = input('config_path')     
  apache_conf_dir = apache_conf(config_path).conf_dir
  apache_logs_dir = "#{apache_conf_dir[0]}/logs"
  log_command = "ls -alH #{apache_logs_dir}"

  if file(apache_logs_dir).exist?
    apache_logs_files = command(log_command).stdout
    describe "Check the owner and group permissions on log files in logs directory" do
      skip "Only system administrators and service accounts should have permissions to these files:\nApache Log Files:\n#{apache_logs_files}"
    end
  else
    describe file(apache_logs_dir).exist? do
      skip "Apache logs directory could not be found. This check has failed."
    end
  end

end