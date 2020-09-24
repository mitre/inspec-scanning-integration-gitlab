# encoding: UTF-8

control 'TCAT-AS-000550' do
    title 'The xpoweredBy attribute must be disabled.'
    desc  'Individual connectors can be configured to display the Tomcat server
    info to clients. This information can be used to identify Tomcat versions which
    can be useful to attackers for identifying vulnerable versions of Tomcat.
    Individual connectors must be checked for the xpoweredBy attribute to ensure
    they do not pass Tomcat server info to clients.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server run the following OS command:
  
      sudo cat $CATALINA_HOME/conf/server.xml |grep -i -C4 xpoweredby.
  
      If any connector elements contain xpoweredBy=\'true\', this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user, edit the
    $CATALINA_HOME/conf/server.xml file.
  
      Examine each $Connector </Connector> element, if the element contains
    xpoweredBy=\'true\', modify the statement to read \', xpoweredBy=\'false\'.
  
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000141-AS-000095'
    tag gid: 'TCAT-AS-000550'
    tag rid: 'TCAT-AS-000550_rule'
    tag stig_id: 'TCAT-AS-000550'
    tag fix_id: 'F-TCAT-AS-000550_fix'
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    x_powered_by = tomcat_server_file["//Connector/@xpoweredBy"]
    if !x_powered_by.empty?
        xPoweredBy.each do |item|
            describe item do 
                it { should cmp "false" }
            end 
        end
    else 
        describe x_powered_by do 
            skip "There is no xpoweredBy param set for Connector. Skipping this check"
        end 
    end
  
end