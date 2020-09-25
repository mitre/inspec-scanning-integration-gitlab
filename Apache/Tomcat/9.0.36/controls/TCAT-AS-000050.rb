# encoding: UTF-8

control 'TCAT-AS-000040' do
    title 'TLS 1.2 must be used on secured HTTP connectors.'
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
      sudo systemctl reload-daemon
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000015-AS-000010'
    tag gid: 'TCAT-AS-000040'
    tag rid: 'TCAT-AS-000040_rule'
    tag stig_id: 'TCAT-AS-000040'
    tag fix_id: 'F-TCAT-AS-000040_fix'
    tag cci: ['CCI-001453']
    tag nist: ['AC-17 (2)']
    
    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml") 
    hosts = tomcat_server_file["//Host"].count 
    valves = tomcat_server_file["//Valve"].count  
    describe hosts do 
        it { should eq valves } 
    end 

end