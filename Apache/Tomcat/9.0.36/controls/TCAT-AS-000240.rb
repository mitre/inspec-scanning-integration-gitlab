# encoding: UTF-8

control 'TCAT-AS-000240' do
    title 'Date and time of events must be logged.'
    desc  'The access logfile format is defined within a Valve that implements
    the org.apache.catalina.valves.AccessLogValve interface within the
    /opt/tomcat/server.xml configuration file: The %t pattern code is included in
    the pattern element and logs the date and time of the event. Including the date
    pattern in the log configuration provides useful information about the time of
    the event which is critical for troubleshooting and forensic investigations.'
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
  
       If the pattern= statement does notinclude %t, this is a finding.
    '
    desc  'fix', '
      As a privileged user on the Tomcat server:
  
      Edit the $CATALINA_HOME/conf/server.xml file.
  
      Modify the <Valve> element(s) nested within the $Host element(s).
  
      Change the AccessLogValve setting to include %t in the pattern= statement.
  
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
    tag gtitle: 'SRG-APP-000096-AS-000059'
    tag gid: 'TCAT-AS-000240'
    tag rid: 'TCAT-AS-000240_rule'
    tag stig_id: 'TCAT-AS-000240'
    tag fix_id: 'F-TCAT-AS-000240_fix'
    tag cci: ['CCI-000131']
    tag nist: ['AU-3']
  
    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    patterns = tomcat_server_file["//Valve/@pattern"]
    patterns.each do |pattern|
        describe pattern do
            it { should include '%t' }
        end
    end
end