# encoding: UTF-8

control 'TCAT-AS-000480' do
    title 'Diagnostic tracing must be disabled.'
    desc  '
      HTTP Trace provides debugging and diagnostics information for a given
    request. Diagnostic information, such as that found in the response to a Trace
    request, often contains sensitive information that may useful to an attacker.
  
      By preventing Tomcat from providing this information, the risk of leaking
    sensitive information to a potential attacker is reduced.
  
      HTTP trace is configured via the connector elements in the server.xml file.
    Each connector element represents an endpoint on the tomcat server which
    receives and responds to client requests so each connector on the server must
    be evaluated for the HTTP trace setting.
    '
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server run the following OS command:
  
      sudo cat $CATALINA_HOME/conf/server.xml | grep -i connector
  
      Review each connector element, ensure each connector does not have an
    \'allowTrace\' setting or ensure the \'allowTrace\' setting is set to false.
  
      <Connector ... allowTrace=\'false\' />
  
      Do the same for each application by checking every
    $CATALINA_HOME/webapps/<APP_NAME>/WEBINF/web.xml file on the system.
  
      sudo cat $CATALINA_HOME/webapps/<APP_NAME>/WEBINF/web.xml |grep -i
    connector
  
      If a connector element in the server.xml file or in any of the <APP
    NAME>/WEBINF/web.xml files contains the \'allow Trace = true\' statement, this
    is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user, edit the xml files containing
    the \'allow Trace=true\' statement.
  
      Remove the \'allow Trace=true\' statement from the affected xml
    configuration files and restart the Tomcat server:
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000141-AS-000095'
    tag gid: 'TCAT-AS-000480'
    tag rid: 'TCAT-AS-000480_rule'
    tag stig_id: 'TCAT-AS-000480'
    tag fix_id: 'F-TCAT-AS-000480_fix'
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']
    
    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    allow_trace = tomcat_server_file["//Connector/@allowTrace"]
    
    if !allow_trace.empty?
        allow_trace.each do |trace|
            describe trace do 
                it { should cmp "false" }
            end
        end
    else 
        describe allow_trace.empty? do 
            it { should cmp "true" }
        end
    end

    apps = command("ls $CATALINA_HOME/webapps/").stdout.split
    ignore = ['docs', 'examples', 'host-manager', 'manager', 'ROOT']

    ignore.each do |x|
      if apps.include?(x)
        apps.delete(x)
      end
    end

    if !apps.empty?
        apps.each do |app|
            web_app = xml("/usr/local/tomcat/webapps/#{app}/WEB-INF/web.xml") 
            web_allow_trace = web_app["//Connector/@allowTrace"]

            if !web_allow_trace.empty?
                web_allow_trace.each do |trace|
                    describe trace do 
                        it { should cmp "false" }
                    end
                end
            else 
                describe web_allow_trace.empty? do 
                    it { should cmp "true" }
                end
            end
        end
    
    end
  
end