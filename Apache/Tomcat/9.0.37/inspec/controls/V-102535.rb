# encoding: UTF-8

control 'V-102535' do
  title 'Default error pages for manager application must be customized.'
  desc  "Default error pages that accompany the manager application provide
educational information on how to configure user accounts and groups for
accessing the manager application. These error pages provide responses to 401
(Unauthorized), 403 (Forbidden), and 404 (Not Found) JSP error codes and should
not exist on production systems."
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server console, run the following command:

    sudo cat $CATALINA_BASE/webapps/manager/WEB-INF/jsp/401.jsp

    Repeat for the 402.jsp and 403.jsp files.

    The default error files contain sample passwords and user accounts.

    If the error files contained in this folder are not customized and sample
information removed, this is a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user:

    sudo cd $CATALINA_BASE/webapps/manager/WEB-INF/jsp/

    Use a file editor like nano or vi and edit the 401, 402, and 403 jsp files.
Remove account information and make the files reflect generic error information
that assists users but does not provide sample data to users.

    Save the file and restart Tomcat:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag gid: 'V-102535'
  tag rid: 'SV-111475r1_rule'
  tag stig_id: 'TCAT-AS-000930'
  tag fix_id: 'F-108067r1_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe "Error pages includes educational information on how to configure Tomcat as responses to the 401
  (Unauthorized), 403 (Forbidden), and 404 (Not Found) JSP error codes and should not exist on production systems" do 
    skip "For the $CATALINA_HOME/webapps/manager/WEB-INF/jsp/401.jsp and 
    the ..402.jsp and ..403.jsp pages. Remove default and sensitive infomation."
  end

end

