# encoding: UTF-8

control 'TCAT-AS-000020' do
  title 'Secured connectors must be configured to use strong encryption
    ciphers.'
  desc  '
    The Tomcat $Connector element controls the SSL/TLS protocol and the
    associated ciphers used. If a strong cipher is not selected, an attacker may be
    able to circumvent encryption protections that are configured for the
    connector. Strong ciphers must be employed when configuring a secured
    connector.

    The configuration attribute and its values depend on what HTTPS
    implementation the user is utilizing. The user may be utilizing either
    Java-based implementation (aka JSSE) with BIO and NIO connectors or
    OpenSSL-based implementation with APR connector.
  '
  desc  'rationale', ''
  desc  'check', '
    From the Tomcat server console, run the following command:

    sudo grep -i ciphers $CATALINA_HOME/conf/server.xml.

    Examine each $Connector statement that is not a redirect to a secure port.
    If insecure ciphers are specified, this is a finding.
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
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag gid: 'TCAT-AS-000020'
  tag rid: 'TCAT-AS-000020_rule'
  tag stig_id: 'TCAT-AS-000020'
  tag fix_id: 'F-TCAT-AS-000020_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    connectors = tomcat_server_file["//Connector"]
    ssl_enabled_protocols = tomcat_server_file["//Connector/@SSLEnabledProtocols"]

    if !ssl_enabled_protocols.empty?
        describe connectors.count do
            it { should eq ssl_enabled_protocols.count }
        end

        ssl_enabled_protocols.each do |item|
            describe item do
                it { should cmp "TLSv1.2" }
            end
        end
    else
        describe ssl_enabled_protocols.empty? do
            it { should cmp "false" }
        end
    end
end