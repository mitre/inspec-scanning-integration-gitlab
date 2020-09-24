# encoding: UTF-8

control 'TCAT-AS-000970' do
    title 'Idle timeout for management application must be set to 10 minutes.'
    desc  'Tomcat can set idle session timeouts on a per application basis. The
    management application is provided with the Tomcat installation and is used to
    manage the applications that are installed on the Tomcat Server. Setting the
    idle timeout for the management application will kill the admin user\'s session
    after 10 minutes of inactivity. This will limit the opportunity for
    unauthorized persons to hijack the admin session. This setting will also affect
    the default timeout behavior of all hosted web applications. To adjust the
    individual hosted application settings that are not related to management of
    the system, modify the individual application web.xml file if application
    timeout requirements differ from the STIG.'
    desc  'rationale', ''
    desc  'check', '
      If the manager application has been deleted from the system, this is not a
    finding.
  
      From the Tomcat server as a privileged user, run the following commands:
  
      sudo grep -i session-timeout
    $CATALINA_HOME/webapps/manager/META-INF/web.xml
  
      sudo grep -i session-timeout
      $CATALINA_HOME/conf/web.xml
  
      If the session-timeout setting is not configured to be 10 minutes in at
    least one of these files, this is a finding.
    '
    desc  'fix', '
      If the manager application has been deleted from the system, this is not a
    finding.
  
      From the Tomcat server as a privileged user:
  
      To affect session timeout for all applications including the management
    application, edit the:
      $CATALINA_HOME/conf/web.xml file.
  
      To affect session timeout for the management application only, edit the:
      $CATALINA_HOME/webapps/manager/META-INF/web.xml file.
  
      Locate the session-timeout setting located within the session-config
    element.
  
      Modify the session-timeout setting to be 10 minutes.
  
      Save the file.
  
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000295-AS-000263'
    tag gid: 'TCAT-AS-000970'
    tag rid: 'TCAT-AS-000970_rule'
    tag stig_id: 'TCAT-AS-000970'
    tag fix_id: 'F-TCAT-AS-000970_fix'
    tag cci: ['CCI-002361']
    tag nist: ['AC-12']

    tomcat_web_files = ["/usr/local/tomcat/conf/web.xml", "/usr/local/tomcat/webapps/manager/META-INF/web.xml"]
    tomcat_web_files.each do |web_file|
        if file(web_file).exist?
            describe xml(web_file)["//session-timeout"] do 
                it { should cmp "10" }
            end
        end
    end
  
end