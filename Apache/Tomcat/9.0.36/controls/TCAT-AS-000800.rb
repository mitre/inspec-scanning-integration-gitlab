# encoding: UTF-8

control 'TCAT-AS-000800' do
    title 'Tomcat servers must mutually authenticate proxy or load balancer
    connections.'
    desc  'Tomcat servers are often placed behind a proxy when exposed to both
    trusted and untrusted networks. This is done for security and performance
    reasons. Tomcat does provide an HTTP server that can be configured to make
    hosted applications available to clients directly. However, this HTTP server
    has performance limitations and is not intended to be used on an enterprise
    scale. Exposing this service to untrusted networks also violates the layered
    security model and creates elevated risk of attack. To address these issues, a
    proxy or load balancer can be placed in front of the Tomcat server. To ensure
    the proxied connection is not spoofed, SSL mutual authentication must be
    employed between Tomcat and the proxy.'
    desc  'rationale', ''
    desc  'check', '
      Review system security plan and/or system architecture documentation and
    interview the system admin. Identify any proxy servers or load balancers that
    provide services for the Tomcat server. If there are no load balancers or
    proxies in use, this is not a finding.
  
      If there is a documented risk acceptance for not mutually authenticating
    proxy of load balancer connections due to operational issues, this is not a
    finding.
  
      Using the aforementioned documentation, identify each Tomcat IP address
    that is served by a load balancer or proxy.
  
      From the Tomcat server as a privileged user, review the
    $CATALINA_HOME/conf/server.xml file. Review each $Connector element for the
    address setting and the clientAuth setting.
  
      sudo grep -i -B1 -A5 connector $CATALINA_HOME/conf/server.xml
  
      If a connector has a configured IP address that is proxied or load balanced
    and the clientAuth setting is not \'true\', this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user, edit the
    $CATALINA_HOME/conf/server.xml file.
  
      Modify each $Connector element where the IP address is behind a proxy or
    load balancer.
  
      Set clientAuth=\'true\' then identify the applications that are associated
    with the connector and edit the associated web.xml files. Assure the
    <auth-method> is set to CLIENT-CERT.
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000219-AS-000147'
    tag gid: 'TCAT-AS-000800'
    tag rid: 'TCAT-AS-000800_rule'
    tag stig_id: 'TCAT-AS-000800'
    tag fix_id: 'F-TCAT-AS-000800_fix'
    tag cci: ['CCI-001184']
    tag nist: ['SC-23']

    describe "This is a manual fix" do 
        skip "Review the SSP or interview the system admin. If there are any Tomcat IP addresses that are served by a load balancer
        or proxy. Check each <Connector> element for the IP address and ensure the clientAuth setting is 'True'"
    end
    
end