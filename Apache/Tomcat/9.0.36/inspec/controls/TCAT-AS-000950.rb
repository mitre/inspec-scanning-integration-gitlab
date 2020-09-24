# encoding: UTF-8

control 'TCAT-AS-000950' do
    title 'Tomcat server version must not be sent with warnings and errors.'
    desc  'Remove version string from HTTP error messages by repacking
    CATALINA_HOME/server/lib/catalina.jar with an updated ServerInfo.properties
    file. This will modify the server information that is provided in error and
    warning responses.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server, cd to the $CATALINA_HOME/lib folder. As a
    privileged user run the following case-sensitive command:
  
      sudo jar -xf catalina.jar org/apache/catalina/util/ServerInfo.properties
  
      Check the ServerInfo.properties file.
      sudo grep -i server org/apache/catalina/util/ServerInfo.properties
  
      If server.info=Apache Tomcat or server.number=the actual Tomcat version,
    this is a finding.
    '
    desc  'fix', '
      From the Tomcat server, cd to the $CATALINA_HOME/lib folder. As a
    privileged user run the following case-sensitive command:
  
      sudo jar -xf catalina.jar org/apache/catalina/util/ServerInfo.properties
  
      Edit the ServerInfo.properties file.
      sudo nano org/apache/catalina/util/ServerInfo.properties
  
      Change server.info and server.number to read:
      server.info=Nunya
      server.number=1.2.3.4
  
      Save the ServerInfo.properties file.
  
      Run the following command to update the catalina.jar file:
      sudo jar -uf catalina.jar org/apache/catalina/util/ServerInfo.properties
  
      Restart the Tomcat server:
      sudo systemctl restart tomcat
      sudo rm -rf opt/
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000267-AS-000170'
    tag gid: 'TCAT-AS-000950'
    tag rid: 'TCAT-AS-000950_rule'
    tag stig_id: 'TCAT-AS-000950'
    tag fix_id: 'F-TCAT-AS-000950_fix'
    tag cci: ['CCI-001314']
    tag nist: ['SI-11 b']

    describe "This is a manual check" do 
        skip "Edit the ServerInfo.properties file to modify the server information 
        that is provided in error and warning responses."
    end
  
end