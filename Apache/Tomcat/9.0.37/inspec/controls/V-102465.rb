# encoding: UTF-8

control 'V-102465' do
  title 'HTTP status code must be logged.'
  desc  "The access logfile format is defined within a Valve that implements
the org.apache.catalina.valves.AccessLogValve interface within the
/opt/tomcat/server.xml configuration file: The %s pattern code is included in
the pattern element and logs the server response code associated with the event
e.g. 200 OK or 400 Bad Request. Including the status pattern in the log
configuration provides useful server response information about the event which
is critical for troubleshooting and forensic investigations."
  desc  'rationale', ''
  desc  'check', "
    As an elevated user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Review all \"Valve\" elements.

    If the pattern= statement does not include %s, this is a finding.

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

    Modify the <Valve> element(s) nested within the $Host element(s).

    Change the AccessLogValve setting to include %s in the pattern= statement.

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
  tag gtitle: 'SRG-APP-000097-AS-000060'
  tag gid: 'V-102465'
  tag rid: 'SV-111411r1_rule'
  tag stig_id: 'TCAT-AS-000260'
  tag fix_id: 'F-108003r1_fix'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  access_log_valves = tomcat_server_file["//Valve/@className"].reject {|name| !name.include? "org.apache.catalina.valves.AccessLogValve" }
  patterns = tomcat_server_file["//Valve/@pattern"].reject {|pattern| !pattern.include? "%s" }
  
  describe 'Each Valve element of class AccessLogValve must have the "%s" included in the pattern in order to log the server response code in the log file' do 
    subject { access_log_valves.count } 
    it {should cmp patterns.count }
  end

end

