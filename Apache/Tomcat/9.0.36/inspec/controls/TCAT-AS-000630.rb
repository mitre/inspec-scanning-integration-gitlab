# encoding: UTF-8

control 'TCAT-AS-000630' do
    title 'SSL must be enabled on JMX.'
    desc  '
      Java Management Extensions (JMX) provides the means for enterprises to
    remotely manage the Java VM and can be used in place of the local manager
    application that comes with Tomcat.
  
      JMX management is configured via the Tomcat CATALINA_OPTS setting
    maintained in the /etc/systemd/system/tomcat.service file for Ubuntu systemd
    UNIX. For Linux OS flavors other than Ubuntu, use the relevant OS commands.
  
      Management tasks such as monitoring and control of applications is
    accomplished via the jmxremote servlet. If authentication is disabled, an
    attacker only needs to know the port number in order to manage and control
    hosted Java applications.
    '
    desc  'rationale', ''
    desc  'check', '
      JMX management is configured via the Tomcat CATALINA_OPTS environment
    variable setting maintained in the /etc/systemd/system/tomcat.service file for
    Ubuntu systemd UNIX. For other flavors of Linux, this location may vary.
  
      As a privileged user from the Tomcat server run the following command:
  
      grep -i jmxremote /etc/systemd/system/tomcat.service
  
      Review output, if there are no results displayed, jmxremote management
    extensions are not used, and this requirement is NA.
  
      If the JMXremote setting is configured and jmxremote.ssl=\'false, this is a
    finding.
  
      EXAMPLE:
      -Dcom.sun.management.jmxremote
      -Dcom.sun.management.jmxremote.authenticate=false
      -Dcom.sun.management.jmxremote.ssl=false
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
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000153-AS-000104'
    tag gid: 'TCAT-AS-000630'
    tag rid: 'TCAT-AS-000630_rule'
    tag stig_id: 'TCAT-AS-000630'
    tag fix_id: 'F-TCAT-AS-000630_fix'
    tag cci: ['CCI-000770']
    tag nist: ['IA-2 (5)']

    tomcat_service_file = "/etc/systemd/system/tomcat.service"
    environment = command("grep -i jmxremote #{tomcat_service_file}").stdout.split(" ")

    if !environment.empty?
        environment.each do |param| 
            if param.includes? "jmxremote.ssl"
                describe param.split("=")[1] do 
                    it { should include "true" }
                end
            end 
        end
    else 
        describe environment do 
            skip "JMX SSL param not found. Skipping this check"
        end
    end 
  
end