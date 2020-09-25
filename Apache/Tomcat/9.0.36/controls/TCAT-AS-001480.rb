# encoding: UTF-8

control 'TCAT-AS-001480' do
    title 'TLS 1.2 must be used on secured connectors.'
    desc  'Using older versions of TLS introduces security vulnerabilities that
    exist in the older versions of the protocol. Tomcat by default will use all
    available versions of the SSL/TLS protocols unless the version is explicitly
    defined in the SSL configuration attribute for the associated connector. This
    introduces the opportunity for the client to negotiate the use of an older
    protocol version and increases the risk of compromise of the Tomcat server. All
    connectors must use TLS 1.2.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server console, run the following command:
  
      sudo cat $CATALINA_HOME/conf/server.xml.
  
      Examine each $Connector </Connector> statement.
  
      For every HTTP protocol connector:
      Verify the SSLEnabledProtocols=\'TLSv1.2\' flag is set on each connector.
  
      If the SSLEnabledProtocols setting is not set to TLSv1.2 or greater, this
    is a finding.
    '
    desc  'fix', '
      As a privileged user on the Tomcat server, edit the
    $CATALINA_HOME/conf/server.xml and modify the $Connector …</Connector> element.
  
      Add the \'SSLEnabledProtocols=\' flag to the connector or modify the
    existing flag.
  
      Set SSLEnabledProtocols=\'TLS1.2\'. Save the server.xml file and restart
    Tomcat:
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000439-AS-000155'
    tag gid: 'TCAT-AS-001480'
    tag rid: 'TCAT-AS-001480_rule'
    tag stig_id: 'TCAT-AS-001480'
    tag fix_id: 'F-TCAT-AS-001480_fix'
    tag cci: ['CCI-002418']
    tag nist: ['SC-8']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    connectors_count = tomcat_server_file["//Connector"].count 
    ssl_enabled_protocols = tomcat_server_file["//Connector/@SSLEnabledProtocols"]

    describe connectors_count do 
        it { should eq ssl_enabled_protocols.count }
    end

    ssl_enabled_protocols.each do |item|
        describe item do 
            it { should cmp "TLSv1.2" }
        end
    end 

end