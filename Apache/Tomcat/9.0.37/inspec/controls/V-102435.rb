# encoding: UTF-8

control 'V-102435' do
  title "AccessLogValve must be configured for each application context.\n"
  desc  "Tomcat has the ability to host multiple contexts (applications) on one
physical server by using the $Host$Context attribute. This allows the admin to
specify audit log settings on a per application basis.


  "
  desc  'rationale', ''
  desc  'check', "
    As an elevated user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Review for all $Context elements.

    If a <Valve className=\"org.apache.catalina.valves.AccessLogValve\" .../>
element is not defined within each $Context element, this is a finding.

    EXAMPLE:

    <Context
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\"
directory=\"logs\"
                   prefix=\"application_name_log\" suffix=\".txt\"
                   pattern=\"\"%h %l %t %u \"%r\" %s %b\" />
      ...
    />
  "
  desc  'fix', "
    As a privileged user on the Tomcat server:

    Edit the $CATALINA_BASE/conf/server.xml file.

    Create a <Valve> element that is nested within the $Context element
containing an AccessLogValve.

    EXAMPLE:

    <Context
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\"
directory=\"logs\"
                   prefix=\"application_name_log\" suffix=\".txt\"
                   pattern=\"%h %l %t %u \"%r\" %s %b\" />
      ...
    />

    Restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag satisfies: ['SRG-APP-000016-AS-000013', 'SRG-APP-000080-AS-000045',
'SRG-APP-000089-AS-000050', 'SRG-APP-000091-AS-000052',
'SRG-APP-000095-AS-000056', 'SRG-APP-000098-AS-000061',
'SRG-APP-000099-AS-000062']
  tag gid: 'V-102435'
  tag rid: 'SV-111379r1_rule'
  tag stig_id: 'TCAT-AS-000050'
  tag fix_id: 'F-107977r3_fix'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000133', 'CCI-000134',
'CCI-000166', 'CCI-000169', 'CCI-000172']
  tag nist: ['AC-17 (1)', 'AU-3', 'AU-3', 'AU-3', 'AU-10', 'AU-12 a', 'AU-12 c']

  
  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml") 
  contexts = tomcat_server_file["//Context"]
  access_log_valves = tomcat_server_file["//Context/Valve/@className"].reject {|name| !name.include? "org.apache.catalina.valves.AccessLogValve" }

  only_if('Context container is not defined in server.xml. Skipping this check.') do 
    contexts.empty?
  end

  describe "Each Context container must have a nested Valve element with the AccessLogValve class name defined" do 
    subject { contexts.count }
    it { should eq access_log_valves.count } 
  end 

end