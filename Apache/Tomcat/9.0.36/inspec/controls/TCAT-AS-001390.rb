# encoding: UTF-8

control 'TCAT-AS-001390' do
    title 'Multifactor certificate-based tokens (CAC) must be used when accessing
    the management interface.'
    desc  'Password authentication does not provide sufficient security control
    when accessing a management interface. DoD has specified that the CAC will be
    used when authenticating and passwords will only be used when CAC
    authentication is not a plausible solution. Tomcat provides the ability to do
    certificate-based authentication and client authentication, therefore the
    Tomcat server must be configured to use CAC.'
    desc  'rationale', ''
    desc  'check', '
      If the manager application has been deleted from the Tomcat server, this is
    not a finding. From the Tomcat server as a privileged user, issue the following
    command:
  
      sudo grep -i auth-method $CATALINA_HOME/webapps/manager/WEB-INF/web.xml
  
      If the <Auth-Method> for the web manager application is not set to
    CLIENT-CERT, this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user, edit the
    $CATALINA_HOME/webapps/manager/WEB-INF/web.xml file and modify the auth-method
    for the manager application security constraint.
  
      sudo nano $CATALINA_HOME/webapps/manager/WEB-INF/web.xml
  
      Locate <auth-method> contained within the <login-config> section, modify
    <auth-method> to specify CLIENT-CERT.
  
      EXAMPLE:
      <auth-method>CLIENT-CERT</auth-method>
  
      In addition, the connector used for accessing the manager application must
    be configured to require client authentication by setting clientAuth=\'true\'
    and the manager application roles must be configured in the LDAP server.
  
      Restart the Tomcat server:
      sudo systemctl restart tomcat
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000403-AS-000248'
    tag gid: 'TCAT-AS-001390'
    tag rid: 'TCAT-AS-001390_rule'
    tag stig_id: 'TCAT-AS-001390'
    tag fix_id: 'F-TCAT-AS-001390_fix'
    tag cci: ['CCI-002010']
    tag nist: ['IA-8 (1)']

    tomcat_manager_web_file = "/usr/local/tomcat/webapps/manager/WEB-INF/web.xml"
 
    only_if('Manager application is not installed. Skipping this check.') do 
        file(tomcat_manager_web_file).exist?
    end

    describe xml(tomcat_manager_web_file)["//auth-method"] do
        it { should cmp "CLIENT-CERT" } 
    end
  
end