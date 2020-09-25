# encoding: UTF-8

control 'V-102553' do
  title 'Application user name must be logged.'
  desc  "The access logfile format is defined within a Valve that implements
the org.apache.catalina.valves.AccessLogValve interface within the
/opt/tomcat/server.xml configuration file: The %u pattern code is included in
the pattern element and logs the username used to authenticate to an
application. Including the username pattern in the log configuration provides
useful information about the application user who is logging in, which is
critical for troubleshooting and forensic investigations."
  desc  'rationale', ''
  desc  'check', "
    As an elevated user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Review all \"Valve\" elements.

    If the pattern= statement does not include %u, this is a finding.

    EXAMPLE:
    <Host name=\"localhost\"  appBase=\"webapps\"
                unpackWARs=\"true\" autoDeploy=\"false\">
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\"
directory=\"logs\"
                   prefix=\"localhost_access_log\" suffix=\".txt\"
                   pattern=\"%h %l %t %u \"%r\" %s %b\" />
      ...
    </Host>
  "
  desc  'fix', "
    As a privileged user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Modify the <Valve> element that is nested beneath the $Host element. Change
the AccessLogValve setting to include %u in the pattern= statement.

    EXAMPLE:
    <Host name=\"localhost\"  appBase=\"webapps\"
                unpackWARs=\"true\" autoDeploy=\"false\">
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\"
directory=\"logs\"
                   prefix=\"localhost_access_log\" suffix=\".txt\"
                   pattern=\"%h %l %t %u \"%r\" %s %b\" />
      ...
    </Host>

    Restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000343-AS-000030'
  tag gid: 'V-102553'
  tag rid: 'SV-111493r1_rule'
  tag stig_id: 'TCAT-AS-001080'
  tag fix_id: 'F-108085r2_fix'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  access_log_valves = tomcat_server_file["//Valve/@className"].reject {|name| !name.include? "org.apache.catalina.valves.AccessLogValve" }
  patterns = tomcat_server_file["//Valve/@pattern"].reject {|pattern| !pattern.include? "%u" }
  
  describe 'Each Valve element of class AccessLogValve must have the "%u" included in the pattern in order to log the username in the log file' do 
    subject { access_log_valves.count } 
    it {should cmp patterns.count }
  end

end

