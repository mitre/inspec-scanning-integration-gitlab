# encoding: UTF-8

control 'TCAT-AS-000930' do
    title 'Default error pages for manager application must be customized.'
    desc  'Default error pages that accompany the manager application provide
    sensitive information to potential attackers. These error pages provide
    responses to 401, 402, and 403 error codes and must be modified so the error
    responses do not provide clients with any sensitive information.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server console, run the following command:
  
      sudo cat $CATALINA_HOME/webapps/manager/WEB-INF/jsp/401.jsp
  
      Repeat for the 402.jsp and 403.jsp files.
  
      The default error files contain default passwords and user accounts.
  
      If the error files contained in this folder are not customized and default
    account information removed, this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user:
  
      Use a file editor like nano or vi and edit the 401, 402, and 403 jsp files.
    Remove sensitive account information and make the files reflect generic error
    information that assists users but does not provide sensitive data to users.
  
      Save the file and restart Tomcat:
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000267-AS-000170'
    tag gid: 'TCAT-AS-000930'
    tag rid: 'TCAT-AS-000930_rule'
    tag stig_id: 'TCAT-AS-000930'
    tag fix_id: 'F-TCAT-AS-000930_fix'
    tag cci: ['CCI-001314']
    tag nist: ['SI-11 b']

    describe "This is a manual check" do 
        skip "For the $CATALINA_HOME/webapps/manager/WEB-INF/jsp/401.jsp and 
        the ..402.jsp and ..403.jsp pages. Remove default and sensitive infomation."
    end
  
end