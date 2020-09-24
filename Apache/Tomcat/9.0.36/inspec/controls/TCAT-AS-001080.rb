# encoding: UTF-8

control 'TCAT-AS-001080' do
    title 'Application user name must be logged.'
    desc  'The access logfile format is defined within a Valve that implements
    the org.apache.catalina.valves.AccessLogValve interface within the
    /opt/tomcat/server.xml configuration file: The %u pattern code is included in
    the pattern element and logs the username used to authenticate to an
    application. Including the username pattern in the log configuration provides
    useful information about the application user who is logging in, which is
    critical for troubleshooting and forensic investigations.'
    desc  'rationale', ''
    desc  'check', '
      As an elevated user on the Tomcat server:
  
      Edit the $CATALINA_HOME/conf/server.xml file.
  
      Review all <Valve> elements. If the pattern= statement does notinclude %u,
    this is a finding.
  
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
  
      Modify the <Valve> element that is nested beneath the $Host element. Change
    the AccessLogValve setting to include %u in the pattern= statement.
  
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
    tag gtitle: 'SRG-APP-000343-AS-000030'
    tag gid: 'TCAT-AS-001080'
    tag rid: 'TCAT-AS-001080_rule'
    tag stig_id: 'TCAT-AS-001080'
    tag fix_id: 'F-TCAT-AS-001080_fix'
    tag cci: ['CCI-002234']
    tag nist: ['AC-6 (9)']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    patterns = tomcat_server_file["//Valve/@pattern"]
    patterns.each do |pattern|
        describe pattern do
            it { should include '%u' }
        end
    end
end