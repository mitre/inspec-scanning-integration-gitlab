# encoding: UTF-8

control 'TCAT-AS-001610' do
  title 'AccessLogValve must be configured per each virtual host.'
  desc  'Tomcat has the ability to host multiple virtual hosts on one physical
  server by using the $Host container attribute. This allows the admin to
  separate hosted applications according to where the domain the application will
  be available. Configuring logs on a per-host basis allows for log management
  that correlates to the virtual host activity.'
  desc  'rationale', ''
  desc  'check', '
    As an elevated user on the Tomcat server:

    Edit the $CATALINA_HOME/conf/server.xml file.

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

    Edit the $CATALINA_HOME/conf/server.xml file.

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
  tag gtitle: 'SRG-APP-000506-AS-000231'
  tag gid: 'TCAT-AS-001610'
  tag rid: 'TCAT-AS-001610_rule'
  tag stig_id: 'TCAT-AS-001610'
  tag fix_id: 'F-TCAT-AS-001610_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    valves = tomcat_server_file["//Valve/@className"]
    describe valves do 
      it { should include "org.apache.catalina.valves.AccessLogValve" }
    end
  
end