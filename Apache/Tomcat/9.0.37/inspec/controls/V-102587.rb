# encoding: UTF-8

control 'V-102587' do
  title 'STRICT_SERVLET_COMPLIANCE must be set to true.'
  desc  "Strict Servlet Compliance forces Tomcat to adhere to standards
specifications including but not limited to RFC2109. RFC2109 sets the standard
for HTTP session management. This setting affects several settings which
primarily pertain to cookie headers, cookie values, and sessions. Cookies will
be parsed for strict adherence to specifications.

    Note that changing a number of these default settings may break some
systems, as some browsers are unable to correctly handle the cookie headers
that result from a strict adherence to the specifications.

    This one setting changes the default values for the following settings:

    org.apache.catalina.core.
    ApplicationContext.GET_RESOURCE_REQUIRE_SLASH
    org.apache.catalina.core.
    ApplicationDispatcher.WRAP_SAME_OBJECT
    org.apache.catalina.core.
    StandardHostValve.ACCESS_SESSION
    org.apache.catalina.session.
    StandardSession.ACTIVITY_CHECK
    org.apache.catalina.session.
    StandardSession.LAST_ACCESS_AT_START
    org.apache.tomcat.util.http.
    ServerCookie.ALWAYS_ADD_EXPIRES
    org.apache.tomcat.util.http.
    ServerCookie.FWD_SLASH_IS_SEPARATOR
    org.apache.tomcat.util.http.
    ServerCookie.PRESERVE_COOKIE_HEADER
    org.apache.tomcat.util.http.
    ServerCookie.STRICT_NAMING
    The resourceOnlyServlets attribute of any Context element.
    The tldValidation attribute of any Context element.
    The useRelativeRedirects attribute of any Context element.
    The xmlNamespaceAware attribute of any Context element.
    The xmlValidation attribute of any Context element.
  "
  desc  'rationale', ''
  desc  'check', "
    If the system has an ISSM risk acceptance for operational issues that arise
due to this setting, this is not a finding.

    From the Tomcat server as a privileged user, run the following command:

    sudo grep -i  strict_servlet /etc/systemd/system/tomcat.service

    If there are no results, or if the
    -Dorg.apache.catalina.STRICT_SERVLET_COMPLIANCE is not set to true, this is
a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user:

    Edit the /etc/systemd/system/tomcat.service file and either add or edit the
org.apache.catalina.STRICT_SERVLET_COMPLIANCE setting.

    Set the org.apache.catalina.STRICT_SERVLET_COMPLIANCE=true

    EXAMPLE:

    CATALINA_OPTS='-Dorg.apache.catalina.STRICT_SERVLET_COMPLIANCE=true'

    Restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-102587'
  tag rid: 'SV-111527r1_rule'
  tag stig_id: 'TCAT-AS-001660'
  tag fix_id: 'F-108119r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  tomcat_service_file = '/etc/systemd/system/tomcat.service'
  environment = command("grep STRICT_SERVLET_COMPLIANCE #{tomcat_service_file}")
  catalina_options = environment.stdout.split(" ")
  param = Array.new 

  catalina_options.each do |option|
    if option.include? "STRICT_SERVLET_COMPLIANCE"
      param.concat(option.split("=")[1])
    end
  end

  describe 'Strict servlet compliance must be set to true' do
    subject { param } 
    it { should include "true" }
  end

end