# encoding: UTF-8

control 'V-102469' do
  title '$CATALINA_BASE/logs folder permissions must be set to 750.'
  desc  "Tomcat file permissions must be restricted. The standard configuration
is to have all Tomcat files owned by root with group Tomcat. While root has
read/write privileges, group only has read permissions, and world has no
permissions. The exceptions are the logs, temp, and work directories that are
owned by the Tomcat user rather than root. This means that even if an attacker
compromises the Tomcat process, they cannot change the Tomcat configuration,
deploy new web applications, or modify existing web applications. The Tomcat
process runs with a umask of 0027 to maintain these permissions."
  desc  'rationale', ''
  desc  'check', "
    Access the Tomcat server from the command line and execute the following OS
command:

    sudo find $CATALINA_BASE/logs -follow -maxdepth 0 -type d \\( \\! -perm 750
\\) -ls

    If ISSM risk acceptance specifies deviation from requirement based on
operational/application needs, this is not a finding if the permissions are set
in accordance with the risk acceptance.

    If no folders are displayed, this is not a finding.

    If results indicate the $CATALINA_BASE/logs folder permissions are not set
to 750, this is a finding.
  "
  desc  'fix', "
    If operational/application requirements specify different file permissions,
obtain ISSM risk acceptance and set permissions according to risk acceptance.

    Run the following command on the Tomcat server:

    sudo find $CATALINA_BASE/logs -follow -maxdepth 0 -type d -print0 | sudo
xargs chmod 750 $CATALINA_BASE/logs
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag gid: 'V-102469'
  tag rid: 'SV-111415r1_rule'
  tag stig_id: 'TCAT-AS-000360'
  tag fix_id: 'F-108007r1_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_log_dir = file("#{catalina_base}/logs").mode 

  describe "$CATALINA_BASE/logs directory permissions must be set to 750" do 
    subject { tomcat_log_dir }
    it { should cmp 750 }
  end

end

