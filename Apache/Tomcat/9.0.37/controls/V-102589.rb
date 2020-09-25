# encoding: UTF-8

control 'V-102589' do
  title 'RECYCLE_FACADES must be set to true.'
  desc  "If RECYCLE_FACADES is true or if a security manager is in use, a new
facade object will be created for each request. This reduces the chances that a
bug in an application might expose data from one request to another. This
setting is configured using environment variable settings. For Linux OS flavors
other than Ubuntu, use the relevant OS commands. For Ubuntu, this setting can
be managed in the /etc/systemd/system/tomcat.service file via the CATALINA_OPTS
variable. This setting is defined in the file and referenced during Tomcat
startup in order to load Tomcat environment variables.

    Technically, the tomcat.service referenced in the check and fix could be
called a different name, for STIG purposes and to provide a standard setting
that can be referred to and obviously is used for Tomcat, tomcat.service was
chosen.
  "
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server as a privileged user, run the following command:

    sudo grep -i  recycle_facades /etc/systemd/system/tomcat.service

    If there are no results, or if the org.apache.catalina.connector.
RECYCLE_FACADES is not =\"true\", this is a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user:

    Edit the /etc/systemd/system/tomcat.service file and either add or edit the
org.apache.catalina.connector. RECYCLE_FACADES setting.

    Set the org.apache.catalina.connector. RECYCLE_FACADES=true

    EXAMPLE:
    Environment='CATALINA_OPTS -Dorg.apache.catalina.connector.
RECYCLE_FACADES=true'

    Restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-102589'
  tag rid: 'SV-111529r1_rule'
  tag stig_id: 'TCAT-AS-001670'
  tag fix_id: 'F-108121r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  tomcat_service_file = '/etc/systemd/system/tomcat.service'
  environment = command("grep RECYCLE_FACADES #{tomcat_service_file}")
  catalina_options = environment.stdout.split(" ")
  recycle_facades = Array.new 

  catalina_options.each do |option|
    if option.include? "RECYCLE_FACADES"
      recycle_facades.push(option.split("=")[1])
    end
  end
  
  describe "The RECYCLE_FACADES setting must be set to true" do 
    subject { recycle_facades }
    it { should include "true" }
  end

end