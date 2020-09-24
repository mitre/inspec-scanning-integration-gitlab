# encoding: UTF-8

control 'V-102477' do
  title "Jar files in the $CATALINA_HOME/bin/ folder must have their
permissions set to 640."
  desc  "Tomcat's file permissions must be restricted. The standard
configuration is to have all Tomcat files owned by root with the group Tomcat.
While root has read/write privileges, tomcat group only has read permissions,
and world has no permissions. The exceptions are the logs, temp, and work
directories that are owned by the Tomcat user rather than root. This means that
even if an attacker compromises the Tomcat process, they cannot change the
Tomcat configuration, deploy new web applications, or modify existing web
applications. The Tomcat process runs with a umask of 007 to maintain these
permissions."
  desc  'rationale', ''
  desc  'check', "
    Access the Tomcat server from the command line and execute the following OS
command:

    sudo find $CATALINA_HOME/bin/*jar -follow -maxdepth 0 -type f  \\( \\!
-perm 640 \\) -ls

    If there are no results, or if .sh extensions are found, this is not a
finding.

    If results indicate any of the jar file permissions contained in the
$CATALINA_HOME/bin folder are not set to 640, this is a finding.
  "
  desc  'fix', "
    Run the following command on the Tomcat server:

    sudo find $CATALINA_HOME/bin/*jar -follow -maxdepth 0 -type f -print0 |
sudo xargs chmod 640 $CATALINA_HOME/bin/*jar
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000120-AS-000080'
  tag gid: 'V-102477'
  tag rid: 'SV-111421r1_rule'
  tag stig_id: 'TCAT-AS-000380'
  tag fix_id: 'F-108013r1_fix'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9']

  permissions = Array.new 
  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_bin_files = command("ls #{catalina_base}/bin").stdout.split

  tomcat_bin_files.each do |b|
    permissions.push(file("#{catalina_base}/bin/#{b}").mode)
  end

  modes = permissions.reject {|mode| mode != 640 }

  describe "Files in the $CATALINA_BASE/bin/ directory must have their permissions set to 640" do 
    subject { tomcat_bin_files.count }
    it { should cmp modes.count }
  end

end

