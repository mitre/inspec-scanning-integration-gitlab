# encoding: UTF-8

control 'V-102497' do
  title 'xpoweredBy attribute must be disabled.'
  desc  "Individual connectors can be configured to display the Tomcat server
info to clients. This information can be used to identify Tomcat versions which
can be useful to attackers for identifying vulnerable versions of Tomcat.
Individual connectors must be checked for the xpoweredBy attribute to ensure
they do not pass Tomcat server info to clients."
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server run the following OS command:

    sudo cat $CATALINA_BASE/conf/server.xml |grep -i -C4 xpoweredby.

    If any connector elements contain xpoweredBy=\"true\", this is a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user, edit the
$CATALINA_BASE/conf/server.xml file.

    Examine each $Connector </Connector> element, if the element contains
xpoweredBy=\"true\", modify the statement to read \", xpoweredBy=\"false\".

    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-102497'
  tag rid: 'SV-111439r1_rule'
  tag stig_id: 'TCAT-AS-000550'
  tag fix_id: 'F-108031r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
  x_powered_by = tomcat_server_file["//Connector/@xpoweredBy"]
  
  describe "The xpoweredBy parameter must be set to false" do 
    subject { x_powered_by }
    it { should_not include "true" } 
  end 

end

