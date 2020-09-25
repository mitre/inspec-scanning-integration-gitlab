# encoding: UTF-8

control 'V-102509' do
  title 'JMX authentication must be secured.'
  desc  "Java Management Extensions (JMX) provides the means to remotely manage
the Java VM. When enabling the JMX agent for remote monitoring, the user must
enable authentication."
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server run the following command:

    sudo grep -I jmxremote.authenticate /etc/systemd/system/tomcat.service
    sudo ps -ef |grep -i jmxremote

    If the results are blank, this is not a finding.

    If the results include:

    -Dcom.sun.management.jmxremote.authenticate=false, this is a finding.
  "
  desc  'fix', "
    If using JMX for management of the Tomcat server, start the Tomcat server
by adding the following command line flags to the systemd startup scripts in
/etc/systemd/system/tomcat.service.

    Environment='CATALINA_OPTS -Dcom.sun.management.jmxremote
-Dcom.sun.management.jmxremote.authenticate=true
-Dcom.sun.management.jmxremote.ssl=true'

    sudo systemctl start tomcat
    sudo systemctl daemon-reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000149-AS-000102'
  tag gid: 'V-102509'
  tag rid: 'SV-111451r1_rule'
  tag stig_id: 'TCAT-AS-000610'
  tag fix_id: 'F-108043r1_fix'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']

  tomcat_service_file = "/etc/systemd/system/tomcat.service"
  environment = command("grep -I jmxremote.authenticate #{tomcat_service_file}").stdout.split(" ")
  jmx_auth_value = Array.new 

  environment.each do |param| 
    if param.includes? "jmxremote.authenticate"
      jmx_auth_value.push(param.split("=")[1])
    end 
  end

  describe "The JMX remote monitoring service must be authenticated" do 
    subject { jmx_auth_value } 
    it { should_not include "false" }
  end

end