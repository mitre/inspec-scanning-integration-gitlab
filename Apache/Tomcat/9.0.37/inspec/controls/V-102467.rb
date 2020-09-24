# encoding: UTF-8

control 'V-102467' do
  title 'The first line of request must be logged.'
  desc  "The access logfile format is defined within a Valve that implements
the org.apache.catalina.valves.AccessLogValve interface within the
/opt/tomcat/server.xml configuration file: The \"%r\" pattern code
is included in the pattern element and logs the first line associated with the
event, namely the request method, URL path, query string, and protocol
(\"\"\" simply specifies a literal double quote). Including the pattern
in the log configuration provides useful information about the time of the
event which is critical for troubleshooting and forensic investigations."
  desc  'rationale', ''
  desc  'check', "
    As an elevated user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Review all \"Valve\" elements.

    If the pattern= statement does not include \"%r\", this is a
finding.

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

    Change the AccessLogValve setting to include \"%r\" in the pattern=
statement.

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
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000097-AS-000060'
  tag gid: 'V-102467'
  tag rid: 'SV-111413r1_rule'
  tag stig_id: 'TCAT-AS-000270'
  tag fix_id: 'F-108005r1_fix'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  access_log_valves = tomcat_server_file["//Valve/@className"].reject {|name| !name.include? "org.apache.catalina.valves.AccessLogValve" }
  patterns = tomcat_server_file["//Valve/@pattern"].reject {|pattern| !pattern.include? "%r" }
  
  describe 'Each Valve element of class AccessLogValve must have the "%r" included in the pattern in order to log the first line associated with the
  event in the log file' do 
    subject { access_log_valves.count } 
    it {should cmp patterns.count }
  end

end

