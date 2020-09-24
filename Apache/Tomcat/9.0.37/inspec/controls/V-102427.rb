# encoding: UTF-8

control 'V-102427' do
  title "The number of allowed simultaneous sessions to the manager application
must be limited.
"
  desc  "The manager application provides configuration access to the Tomcat
server. Access to the manager application must be limited and that includes the
number of sessions allowed to access the management application. A balance must
be struck between the number of simultaneous connections allowed to the
management application and the number of authorized admins requiring access at
any given time.

    Determine the number of authorized admins requiring simultaneous access and
increase the number of allowed simultaneous sessions by a small percentage in
order to help prevent potential lockouts.

    Document that value in the System Security Plan (SSP).
  "
  desc  'rationale', ''
  desc  'check', "
    If the manager application is not in use or has been deleted from the
system, this is not a finding.

    From the Tomcat server as an elevated user run the following command:

    sudo grep -i maxactivesessions $CATALINA_BASE/webapps/manager/
META-INF/context.xml

    If the maxActiveSesions setting is not configured according to the number
of connections defined in the SSP, this is a finding.
  "
  desc  'fix', "
    Determine the number of authorized admins requiring simultaneous access and
increase the number of allowed simultaneous sessions by a small percentage in
order to address potential lockout scenarios. Document that value in the System
Security Plan.

    Review the maxActiveSessions setting in the $CATALINA_BASE/webapps/manager/
META-INF/context.xml configuration file.

    Configure maxActiveSessions setting according to admin access requirements
defined in the SSP.

    EXAMPLE:
    <Manager … maxActiveSessions=\"10\" />
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-102427'
  tag rid: 'SV-111371r1_rule'
  tag stig_id: 'TCAT-AS-000010'
  tag fix_id: 'F-107969r4_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')

  tomcat_manager_context_file = "#{catalina_base}/webapps/manager/META-INF/context.xml"
  max_active_sessions = xml(tomcat_manager_context_file["//manager/@maxActiveSessions"]) 

  only_if('Manager application is not installed. Skipping this check.') do 
    file(tomcat_manager_context_file).exist?
  end
  
  describe "Determine the number of authorized admins requiring simultaneous access" do
    skip "The number of simultaneous access is #{max_active_sessions}. Compare this value with admin access requirements in the Systems Security Plan."
  end
  
end
