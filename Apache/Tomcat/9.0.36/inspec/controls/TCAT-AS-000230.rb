# encoding: UTF-8

control 'TCAT-AS-000230' do
    title 'AccessLogValve must be configured for Catalina engine.'
    desc  '
      The $Engine container represents the entire request processing machinery
    associated with a particular Catalina Service. It receives and processes all
    requests from one or more Connectors, and returns the completed response to the
    Connector for transmission back to the client. The AccessLogValve will log
    activity for the Catalina service.
  
      Exactly one Engine element must be nested inside a Service element,
    following all of the corresponding Connector elements associated with the
    Service.
    '
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
    tag gtitle: 'SRG-APP-000095-AS-000056'
    tag gid: 'TCAT-AS-000230'
    tag rid: 'TCAT-AS-000230_rule'
    tag stig_id: 'TCAT-AS-000230'
    tag fix_id: 'F-TCAT-AS-000230_fix'
    tag cci: ['CCI-000130']
    tag nist: ['AU-3']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml") 
    hosts = tomcat_server_file["//Host"].count 
    valves = tomcat_server_file["//Valve"].count  
    describe hosts do 
        it { should eq valves } 
    end 

end