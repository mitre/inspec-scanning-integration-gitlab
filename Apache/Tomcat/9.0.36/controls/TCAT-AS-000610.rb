# encoding: UTF-8

control 'TCAT-AS-000610' do
    title 'JMX authentication must be secured.'
    desc  'Java Management Extensions (JMX) provides the means to remotely manage
    the Java VM. When enabling the JMX agent for remote monitoring, the user must
    enable authentication.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server run the following command:
  
      sudo grep -I jmxremote.authenticate /etc/systemd/system/tomcat.service
  
      If the results are blank, this is not a finding.
  
      If the results include:
  
      -Dcom.sun.management.jmxremote
      -Dcom.sun.management.jmxremote.authenticate=false, this is a finding.
    '
    desc  'fix', '
      If using JMX for management of the Tomcat server, start the Tomcat server
    by adding the following command line flags to the systemd startup scripts in
    /etc/systemd/system/tomcat.service.
  
      Environment=\'CATALINA_OPTS -Dcom.sun.management.jmxremote
    -Dcom.sun.management.jmxremote.authenticate=true
    -Dcom.sun.management.jmxremote.ssl=true\'
  
      sudo systemctl start tomcat
      sudo systemctl daemon-reload
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000149-AS-000102'
    tag gid: 'TCAT-AS-000610'
    tag rid: 'TCAT-AS-000610_rule'
    tag stig_id: 'TCAT-AS-000610'
    tag fix_id: 'F-TCAT-AS-000610_fix'
    tag cci: ['CCI-000765']
    tag nist: ['IA-2 (1)']

    tomcat_service_file = "/etc/systemd/system/tomcat.service"
    environment = command("grep -I jmxremote.authenticate #{tomcat_service_file}").stdout.split(" ")

    if !environment.empty?
        environment.each do |param| 
            if param.includes? "jmxremote.authenticate"
                describe param.split("=")[1] do 
                    it { should include "true" }
                end
            end 
        end
    else 
        describe environment do 
            skip "JMX authentication params not found. Skipping this check"
        end
    end 

end