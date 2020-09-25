# encoding: UTF-8

control 'TCAT-AS-000820' do
    title 'Tomcat must be configured to generate session IDs using a FIPS 140-2
    approved random number generator.'
    desc  '
      If RECYCLE_FACADES is true or if a security manager is in use, a new facade
    object will be created for each request. This reduces the chances that a bug in
    an application might expose data from one request to another. This setting is
    configured using environment variable settings. For Linux OS flavors other than
    Ubuntu, use the relevant OS commands. For Ubuntu, this setting can be managed
    in the /etc/systemd/system/tomcat.service file via the CATALINA_OPTS variable.
    This setting is defined in the file and referenced during tomcat startup in
    order to load tomcat environment variables.
  
      Technically, the tomcat.service referenced in the check and fix could be
    called a different name; but for STIG purposes and to provide a standard
    setting that can be referred to and obviously is used for Tomcat,
    tomcat.service was chosen.
    '
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server as a privileged user, run the following command:
  
      sudo grep -i  recycle_facades /etc/systemd/system/tomcat.service
  
      If there are no results, or if the org.apache.catalina.connector.
    RECYCLE_FACADES is not configured to load at startup, this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user:
  
      edit the /etc/systemd/system/tomcat.service file and either add or edit the
    org.apache.catalina.connector. RECYCLE_FACADES setting.
  
      Set the org.apache.catalina.connector. RECYCLE_FACADES=true.
  
      EXAMPLE:
      Environment=\'CATALINA_OPTS -Dorg.apache.catalina.connector.
    RECYCLE_FACADES=true\'
  
      Restart the Tomcat server:
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000223-AS-000150'
    tag gid: 'TCAT-AS-000820'
    tag rid: 'TCAT-AS-000820_rule'
    tag stig_id: 'TCAT-AS-000820'
    tag fix_id: 'F-TCAT-AS-000820_fix'
    tag cci: ['CCI-001664']
    tag nist: ['SC-23 (3)']

    tomcat_service_file = '/etc/systemd/system/tomcat.service'
    environment = command("grep RECYCLE_FACADES #{tomcat_service_file}")
    catalina_options = environment.stdout.split(" ")
    
    if !catalina_options.empty?
        catalina_options.each do |option|
            if option.include? "RECYCLE_FACADES"
                describe option.split("=")[1] do 
                    it { should include "true" }
                end
            end
        end
    else
        describe catalina_options do 
            it { should include "RECYCLE_FACADES" }
        end
    end
    
end