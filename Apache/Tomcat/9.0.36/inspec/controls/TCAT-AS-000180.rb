# encoding: UTF-8

control 'TCAT-AS-000180' do
  title 'Role based access controls must be configured for logging.'
  desc  'Application servers utilize role-based access controls in order to
  specify the individuals who are allowed to configure application component
  logable events. The application server must be configured to select which
  personnel are assigned the role of selecting which logable events are to be
  logged.'
  desc  'rationale', ''
  desc  'check', '
    As an elevated user on the Tomcat server:

    Edit the $CATALINA_HOME\\conf\\server.xml file.

    Review for all $Host elements. If a <Valve
  className=\'org.apache.catalina.valves.AccessLogValve\' .../> element is not
  defined for each $Host element, this is a finding.

    EXAMPLE:
    <Host name=\'localhost\'  appBase=\'webapps\'
                unpackWARs=\'true\' autoDeploy=\'false\'>
    ...
    <Valve className=\'org.apache.catalina.valves.AccessLogValve\'
  directory=\'logs\'
                   prefix=\'localhost_access_log\' suffix=\'.txt\'
                   pattern=\'%h %l %t %u &quot;%r&quot; %s %b\' />
      ...
    </Host>
  '
  desc  'fix', '
    As a privileged user on the Tomcat server:

    Edit the $CATALINA_HOME\\conf\\server.xml file.

    Create a <Valve> element that is nested beneath the $Host element
  containing an AccessLogValve.

    EXAMPLE:
    <Host name=\'localhost\'  appBase=\'webapps\'
                unpackWARs=\'true\' autoDeploy=\'false\'>
    ...
    <Valve className=\'org.apache.catalina.valves.AccessLogValve\'
  directory=\'logs\'
                   prefix=\'localhost_access_log\' suffix=\'.txt\'
                   pattern=\'%h %l %t %u &quot;%r&quot; %s %b\' />
      ...
    </Host>

    Restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-AS-000051'
  tag gid: 'TCAT-AS-000180'
  tag rid: 'TCAT-AS-000180_rule'
  tag stig_id: 'TCAT-AS-000180'
  tag fix_id: 'F-TCAT-AS-000180_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml") 
    hosts = tomcat_server_file["//Host"].count 
    valves = tomcat_server_file["//Valve"].count  
    describe hosts do 
        it { should eq valves } 
    end 

end