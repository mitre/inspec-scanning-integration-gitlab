# encoding: UTF-8

control 'TCAT-AS-000470' do
    title 'Stack tracing must be disabled.'
    desc  'Stack tracing provides debugging information from the application call
    stacks when a runtime error is encountered. If stack tracing is enabled, Tomcat
    will provide this call stack information to the requestor which could result in
    the loss of sensitive information or data that could be used to compromise the
    system.'
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
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000141-AS-000095'
    tag gid: 'TCAT-AS-000470'
    tag rid: 'TCAT-AS-000470_rule'
    tag stig_id: 'TCAT-AS-000470'
    tag fix_id: 'F-TCAT-AS-000470_fix'
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