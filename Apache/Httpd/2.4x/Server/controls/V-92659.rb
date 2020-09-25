# encoding: UTF-8

control 'V-92659' do
  title "The Apache web server must have Web Distributed Authoring (WebDAV)
disabled."
  desc  "A web server can be installed with functionality that, by its nature,
is not secure. WebDAV is an extension to the HTTP protocol that, when
developed, was meant to allow users to create, change, and move documents on a
server, typically a web server or web share. Allowing this functionality,
development, and deployment is much easier for web authors.

    WebDAV is not widely used and has serious security concerns because it may
allow clients to modify unauthorized files on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    In a command line, run \"httpd -M | sort\" to view a list of installed
modules.

    If any of the following modules are present, this is a finding:

    dav_module
    dav_fs_module
    dav_lock_module
  "
  desc  'fix', "
    Determine where the \"dav\" modules are located by running the following
command:

    grep -rl \"dav_module\" <'INSTALL PATH'>

    Edit the file and comment out the following modules:

    dav_module
    dav_fs_module
    dav_lock_module

    Restart Apache: apachectl restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: 'V-92659'
  tag rid: 'SV-102747r1_rule'
  tag stig_id: 'AS24-U1-000330'
  tag fix_id: 'F-98901r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  modules_command = "httpd -M | sort"
  installed_modules = command(modules_command).stdout.split 
  
  check_modules = [
    "dav_module",
    "dav_fs_module",
    "dav_lock_module",
  ]

  bad_modules = installed_modules.select do |i|
    check_modules.any? {|j| i.include?(j) }
  end

  describe bad_modules do 
    it "The following modules should be removed from Apache server" do 
      failure_message = "The following modules should be removed: #{bad_modules.join(', ')}"
      expect(bad_modules).to be_empty, failure_message
    end
  end

end

