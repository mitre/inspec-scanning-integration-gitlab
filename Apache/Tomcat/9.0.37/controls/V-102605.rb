# encoding: UTF-8

control 'V-102605' do
  title '$CATALINA_BASE/conf folder permissions must be set to 750.'
  desc  "Tomcat file permissions must be restricted. The standard configuration
is to have all Tomcat files owned by root with group Tomcat. While root has
read/write privileges, group only has read permissions, and world has no
permissions. The exceptions are the logs, temp, and work directories that are
owned by the Tomcat user rather than root. This means that even if an attacker
compromises the Tomcat process, they cannot change the Tomcat configuration,
deploy new web applications, or modify existing web applications. The Tomcat
process runs with a umask of 007 to maintain these permissions.

    If the ISSM determines the operational need to allow application admins
access to change the Tomcat configuration outweighs the risk of limiting that
access, then they can change the group membership to accommodate. Ownership
must not be changed. The ISSM should take the exposure of the system to high
risk networks into account."
  desc  'rationale', ''
  desc  'check', "
    Access the Tomcat server from the command line and execute the following OS
command:

    sudo find $CATALINA_BASE/conf -follow -maxdepth 0 -type d \\( \\! -perm 750
\\) -ls

    If ISSM risk acceptance specifies deviation from requirement based on
operational/application needs, this is not a finding if the permissions are set
in accordance with the risk acceptance.

    If no folders are displayed, this is not a finding.

    If results indicate the $CATALINA_BASE/conf folder permissions are not set
to 750, this is a finding.
  "
  desc  'fix', "
    If operational/application requirements specify different file permissions,
obtain ISSM risk acceptance and set permissions according to risk acceptance.

    Run the following command on the Tomcat server:

    sudo find $CATALINA_BASE/conf -follow -maxdepth 0 -type d -print0 | sudo
xargs chmod 750 $CATALINA_BASE/conf
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-AS-000079'
  tag satisfies: ['SRG-APP-000119-AS-000079', 'SRG-APP-000380-AS-000088']
  tag gid: 'V-102605'
  tag rid: 'SV-111551r1_rule'
  tag stig_id: 'TCAT-AS-000371'
  tag fix_id: 'F-108137r3_fix'
  tag cci: ['CCI-000163', 'CCI-001813']
  tag nist: ['AU-9', 'CM-5 (1)']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_conf_dir = file("#{catalina_base}/conf").mode 

  describe "$CATALINA_BASE/conf directory permissions must be set to 750" do 
    subject { tomcat_conf_dir }
    it { should cmp 750 }
  end

end