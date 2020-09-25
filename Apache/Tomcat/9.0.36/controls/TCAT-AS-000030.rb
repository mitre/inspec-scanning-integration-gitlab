# encoding: UTF-8

control 'TCAT-AS-000030' do
    title 'HTTP Strict Transport Security (HSTS) must be enabled.'
    desc  '
      HTTP Strict Transport Security (HSTS) instructs web browsers to only use
    secure connections for all future requests when communicating with a web site.
    Doing so helps prevent SSL protocol attacks, SSL stripping, cookie hijacking,
    and other attempts to circumvent SSL protection.
    '
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server console, run the following command:
  
      sudo grep -i -A5 -B8 hstsEnable $CATALINA_HOME/conf/web.xml file.
  
      If the httpHeaderSecurity filter is commented out or if hstsEnable is not
    set to \'true\', this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user, edit the web.xml file:
  
      sudo nano $CATALINA_HOME/conf/web.xml file.
  
      Uncomment the existing httpHeaderSecurity filter section or create the
    filter section using the following code:
  
          <filter>
              <filter-name>httpHeaderSecurity</filter-name>
  
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
              <async-supported>true</async-supported>
               <hstsEnabled>true</hstsEnabled>
          </filter>
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000015-AS-000010'
    tag gid: 'TCAT-AS-000030'
    tag rid: 'TCAT-AS-000030_rule'
    tag stig_id: 'TCAT-AS-000030'
    tag fix_id: 'F-TCAT-AS-000030_fix'
    tag cci: ['CCI-001453']
    tag nist: ['AC-17 (2)']
  
    tomcat_web_file = xml("/usr/local/tomcat/conf/web.xml")
    hsts = tomcat_web_file["//hstsEnabled"]

    describe hsts do
        it { should cmp "true" }
    end
    
end