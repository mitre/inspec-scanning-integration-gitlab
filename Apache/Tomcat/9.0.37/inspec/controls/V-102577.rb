# encoding: UTF-8

control 'V-102577' do
  title 'AccessLogValve must be configured for Catalina engine.'
  desc  "The $Engine container represents the entire request processing
machinery associated with a particular Catalina Service. It receives and
processes all requests from one or more Connectors, and returns the completed
response to the Connector for transmission back to the client. The
AccessLogValve will log activity for the Catalina service.

    Exactly one Engine element MUST be nested inside a Service element,
following all of the corresponding Connector elements associated with the
Service.


  "
  desc  'rationale', ''
  desc  'check', "
    As an elevated user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Review the $Engine element. Ensure one AccessLog <Valve> element is nested
within the Engine element.

    If a <Valve className=\"org.apache.catalina.valves.AccessLogValve\" .../>
element is not defined, this is a finding.

    EXAMPLE:
    <Engine name=\"Standalone\" ...>
      ...
      <Valve className=\"org.apache.catalina.valves.AccessLogValve\"
             prefix=\"catalina_access_log\" suffix=\".txt\"
             pattern=\"common\"/>
      ...
    </Engine>
  "
  desc  'fix', "
    As a privileged user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Create a <Valve> element that is nested beneath the $Host element
containing an AccessLogValve.

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
  tag gtitle: 'SRG-APP-000495-AS-000220'
  tag satisfies: ['SRG-APP-000495-AS-000220', 'SRG-APP-000381-AS-000089',
'SRG-APP-000499-AS-000224', 'SRG-APP-000504-AS-000229']
  tag gid: 'V-102577'
  tag rid: 'SV-111517r1_rule'
  tag stig_id: 'TCAT-AS-001560'
  tag fix_id: 'F-108109r1_fix'
  tag cci: ['CCI-000172', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1)']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

  access_log_valves = tomcat_server_file["//Engine/Valve/@className"].reject {|name| !name.include? "org.apache.catalina.valves.AccessLogValve" }
  
  describe 'At least one Valve element of class AccessLogValve must be a nested component in the <Engine> container' do 
    subject { access_log_valves } 
    it {should include "org.apache.catalina.valves.AccessLogValve" }
  end

end

