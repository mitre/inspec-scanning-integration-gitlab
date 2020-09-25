# encoding: UTF-8

control 'V-102431' do
  title "HTTP Strict Transport Security (HSTS) must be enabled.\n"
  desc  "HTTP Strict Transport Security (HSTS) instructs web browsers to only
use secure connections for all future requests when communicating with a
website. Doing so helps prevent SSL protocol attacks, SSL stripping, cookie
hijacking, and other attempts to circumvent SSL protection.


https://community.microfocus.com/t5/Identity-Manager-Tips/Enabling-HTTP-Strict-Transport-Security-HSTS-for-Tomcat-8/ta-p/1776810

    https://stackoverflow.com/questions/27541755/add-hsts-feature-to-tomcat
  "
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server console, run the following command:

    sudo grep -i -A5 -B8 hstsEnable $CATALINA_BASE/conf/web.xml file.

    If the httpHeaderSecurity filter is commented out or if hstsEnable is not
set to \"true\", this is a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user, edit the web.xml file:

    sudo nano $CATALINA_BASE/conf/web.xml file.

    Uncomment the existing httpHeaderSecurity filter section or create the
filter section using the following code:

        <filter>
            <filter-name>httpHeaderSecurity</filter-name>

<filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
            <async-supported>true</async-supported>
             <hstsEnabled>true</hstsEnabled>
        </filter>
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag gid: 'V-102431'
  tag rid: 'SV-111375r1_rule'
  tag stig_id: 'TCAT-AS-000030'
  tag fix_id: 'F-107973r3_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_web_file = xml("#{catalina_base}/conf/web.xml")

  describe "The httpHeaderSecurity filter must be defined" do
    subject { tomcat_web_file["//filter-name"] }
    it { should include "httpHeaderSecurity" }
  end

  describe "The hstsEnabled param must be set to true for the httpHeaderSecurity filter" do
    subject { tomcat_web_file["//hstsEnableds"] }
    it { should cmp "true" }
  end

end

