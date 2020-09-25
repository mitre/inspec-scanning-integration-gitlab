# encoding: UTF-8

control 'V-102483' do
  title 'Stack tracing must be disabled.'
  desc  "Stack tracing provides debugging information from the application call
stacks when a runtime error is encountered. If stack tracing is left enabled,
Tomcat will provide this call stack information to the requestor which could
result in the loss of sensitive information or data that could be used to
compromise the system.  As with all STIG settings, it is acceptable to
temporarily enable for troubleshooting and debugging purposes but the setting
must not be left enabled after troubleshooting tasks have been completed."
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server run the following OS command:

    sudo cat $CATALINA_BASE/conf/server.xml | grep -i connector

    Review each connector element, ensure each connector does not have an
\"allowTrace\" setting or ensure the \"allowTrace\" setting is set to false.

    <Connector ... allowTrace=\"false\" />

    Do the same for each application by checking every
$CATALINA_BASE/webapps/<APP_NAME>/WEBINF/web.xml file on the system.

    sudo cat $CATALINA_BASE/webapps/<APP_NAME>/WEBINF/web.xml |grep -i
connector

    If a connector element in the server.xml file or in any of the <APP
NAME>/WEBINF/web.xml files contains the \"allow Trace = true\" statement, this
is a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user, edit the xml files containing
the \"allow Trace=true\" statement.

    Remove the \"allow Trace=true\" statement from the affected xml
configuration files and restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-102483'
  tag rid: 'SV-111425r1_rule'
  tag stig_id: 'TCAT-AS-000470'
  tag fix_id: 'F-108017r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
  allow_trace = tomcat_server_file["//Connector/@allowTrace"]

  apps = command("ls #{catalina_base}/webapps/").stdout.split
  ignore = ['docs', 'examples', 'host-manager', 'manager', 'ROOT']

  ignore.each do |x|
    if apps.include?(x)
      apps.delete(x)
    end
  end

  if !apps.empty? 
    apps.each do |app|
      app_web = xml("#{catalina_base}/webapps/#{app}/WEBINF/web.xml")
      allow_trace.concat(app_web["//Connector/@allowTrace"])
    end
  end

  describe "if stack tracing is defined in any Connector containers it should be set to false" do 
    subject { allow_trace }
    it { should_not include "true" }
  end

end