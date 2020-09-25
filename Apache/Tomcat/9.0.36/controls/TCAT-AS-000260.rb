# encoding: UTF-8

control 'TCAT-AS-000260' do
    title 'HTTP status code must be logged.'
    desc  'The access logfile format is defined within a Valve that implements
    the org.apache.catalina.valves.AccessLogValve interface within the
    /opt/tomcat/server.xml configuration file: The %s pattern code is included in
    the pattern element and logs the server response code associated with the event
    e.g. 200 OK or 400 Bad Request. Including the status pattern in the log
    configuration provides useful server response information about the event which
    is critical for troubleshooting and forensic investigations.'
    desc  'rationale', ''
    desc  'check', '
      As an elevated user on the Tomcat server:
  
      Edit the $CATALINA_HOME/conf/server.xml file.
  
      Review all <Valve> elements.
  
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
  
       If the pattern= statement does notinclude %s, this is a finding.
    '
    desc  'fix', '
      As a privileged user on the Tomcat server:
  
      Edit the $CATALINA_HOME/conf/server.xml file.
  
      Modify the <Valve> element(s) nested within the $Host element(s).
  
      Change the AccessLogValve setting to include %s in the pattern= statement.
  
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
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000097-AS-000060'
    tag gid: 'TCAT-AS-000260'
    tag rid: 'TCAT-AS-000260_rule'
    tag stig_id: 'TCAT-AS-000260'
    tag fix_id: 'F-TCAT-AS-000260_fix'
    tag cci: ['CCI-000132']
    tag nist: ['AU-3']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    patterns = tomcat_server_file["//Valve/@pattern"]
    patterns.each do |pattern|
        describe pattern do
            it { should include '%s' }
        end
    end
  
end