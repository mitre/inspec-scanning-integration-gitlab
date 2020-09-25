# encoding: UTF-8

control 'TCAT-AS-000100' do
    title 'Connectors must be secured.'
    desc  'The unencrypted HTTP protocol does not protect data from interception
    or alteration which can subject users to eavesdropping, tracking, and the
    modification of received data. To secure an HTTP connector, both the secure and
    scheme flags must be set.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server console, run the following command:
  
      sudo cat $CATALINA_HOME/conf/server.xml.
  
      Examine each <Connector/> element.
  
      For each connector, verify the secure= flag is set to \'true\' and the
    scheme= flag is set to \'https\' on each connector.
  
      If the secure flag is not set to \'true\' and/or the scheme flag is not set
    to \'https\' for each HTTP connector element, this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user, edit the server.xml file.
  
      sudo nano $CATALINA_HOME/conf/server.xml.
  
      Locate each <Connector/> element which is lacking a secure setting.
  
      EXAMPLE Connector:
      <Connector port=\'8080\' protocol=\'HTTP/1.1\'
                     connectionTimeout=\'20000\'
                     redirectPort=\'443\' />
  
      Set or add scheme=\'https\' and secure=\'true\' for each HTTP connector
    element.
  
      EXAMPLE:
      <Connector port=\'443\'
    protocol=\'org.apache.coyote.http11.Http11NioProtocol\' SSLEnabled=\'true\'
          maxThreads=\'150\' scheme=\'https\' secure=\'true\'.../>
  
      Save the server.xml file and restart Tomcat:
      sudo systemctl restart tomcat
      sudo systemctl reload-daemon
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000033-AS-000024'
    tag gid: 'TCAT-AS-000100'
    tag rid: 'TCAT-AS-000100_rule'
    tag stig_id: 'TCAT-AS-000100'
    tag fix_id: 'F-TCAT-AS-000100_fix'
    tag cci: ['CCI-000213']
    tag nist: ['AC-3']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    connector_count = tomcat_server_file["//Connector"].count 
    secure = tomcat_server_file["//Connector/@secure"]
    scheme = tomcat_server_file["//Connector/@scheme"]

    describe connector_count do 
        it { should cmp secure.count }
        it { should cmp scheme.count }
    end 

    if !secure.empty?
        secure.each do |item|
            describe item do 
                it { should cmp "true" }
            end 
        end
    end

    if !scheme.empty?
        scheme.each do |item| 
            describe item do 
                it { should cmp "https" } 
            end
        end
    end

end