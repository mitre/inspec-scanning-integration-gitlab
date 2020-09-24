# encoding: UTF-8

control 'TCAT-AS-000680' do
    title 'TLS 1.2 must be used on secured connectors.'
    desc  'Encryption is the standard method for protecting data during
    transmission. If data is not encrypted with a secure protocol such as TLS 1.2,
    the data can be plainly read (i.e., clear text) and easily compromised.
    Versions of TLS less than 1.1 and SSL versions have known vulnerabilities and
    must not be used.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server console, run the following command:
  
      sudo cat $CATALINA_HOME/conf/server.xml.
  
      Examine each $Connector </Connector> statement.
  
      For every HTTP protocol connector, verify the
    SSLEnabledProtocols=\'TLSv1.2\' flag is set on each connector.
  
      If the SSLEnabledProtocols setting is not set to TLSv1.2 or greater, this
    is a finding.
    '
    desc  'fix', '
      As a privileged user on the Tomcat server, edit the
    $CATALINA_HOME/conf/server.xml and modify the $Connector …</Connector> element.
  
      Add the \'SSLEnabledProtocols=\' flag to the connector or modify the
    existing flag.
  
      Set SSLEnabledProtocols=\'TLS1.2\'.  Save the server.xml file and restart
    Tomcat:
      sudo systemctl restart tomcat
      sudo systemctl reload-daemon
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000172-AS-000120'
    tag gid: 'TCAT-AS-000680'
    tag rid: 'TCAT-AS-000680_rule'
    tag stig_id: 'TCAT-AS-000680'
    tag fix_id: 'F-TCAT-AS-000680_fix'
    tag cci: ['CCI-000197']
    tag nist: ['IA-5 (1) (c)']
    

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