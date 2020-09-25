# encoding: UTF-8

control 'V-92653' do
  title "The Apache web server must have resource mappings set to disable the
serving of certain file types."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and cannot be served to a user, the web
server could deliver to a user web server configuration files, log files,
password files, etc.

    The web server must only allow hosted application file types to be served
to a user, and all other types must be disabled.


  "
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Review any \"Action\" or \"AddHandler\" directives:

    # cat /<path_to_file>/httpd.conf | grep -i \"Action\"
    # cat /<path_to_file>/httpd.conf | grep -i \"AddHandler\"

    If \"Action\" or \"AddHandler\" exist and they configure .exe, .dll, .com,
.bat, or .csh, or any other shell as a viewer for documents, this is a finding.

    If this is not documented and approved by the Information System Security
Officer (ISSO), this is a finding.
  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Disable MIME types for .exe, .dll, .com, .bat, and .csh programs.

    If \"Action\" or \"AddHandler\" exist within the \"httpd.conf\" file and
they configure .exe, .dll, .com, .bat, or .csh, remove those references.

    Restart Apache: apachectl restart

    Ensure this process is documented and approved by the ISSO.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag satisfies: ['SRG-APP-000141-WSR-000081', 'SRG-APP-000141-WSR-000083']
  tag gid: 'V-92653'
  tag rid: 'SV-102741r1_rule'
  tag stig_id: 'AS24-U1-000300'
  tag fix_id: 'F-98895r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  config_path = input('config_path')
  file_endings = [".exe", ".dll", ".com", ".bat", ".csh"]
  actions = apache_conf(config_path).params("Action")
  add_handlers = apache_conf(config_path).params("AddHandler")
  
  only_if("There are no Actions or AddHandlers") do
    !actions.nil? && !add_handlers.nil?
  end
  
  if !actions.nil? && !add_handlers.nil?
    remove_add_handlers = add_handlers.select do |i|
      file_endings.any? {|j| i.include?(j) }
    end
    remove_actions = actions.select do |i|
      file_endings.any? {|j| i.include?(j) }
    end
    remove = remove_add_handlers + remove_actions 
  
  else
    if actions.nil?
      remove = add_handlers.select do |i|
        file_endings.any? {|j| i.include?(j) }
      end
    end
  
    if add_handlers.nil?
      remove = actions.select do |i|
        file_endings.any? {|j| i.include?(j) }
      end
    end
  end 
  
  describe "Certain file types must not be served by the Web Server" do 
    skip "The following files were enabled by Actions/AddHandler directives and should be removed from the Apache configuration file: #{remove.join(', ')}"
  end

end






