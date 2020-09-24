# encoding: UTF-8

control 'V-102495' do
  title 'Autodeploy must be disabled.'
  desc  "Tomcat allows auto-deployment of applications while Tomcat is running.
This can allow untested or malicious applications to be automatically loaded
into production. Autodeploy must be disabled in production.

    This requirement is NA for test and development systems on non-production
networks. For DevSecOps application environments, the ISSM may authorize
autodeploy functions on a production Tomcat system if the mission need
specifies it and an application security vulnerability testing and assurance
regimen is included in the DevSecOps process.
  "
  desc  'rationale', ''
  desc  'check', "
    If the SSP associated with the Host contains ISSM documented approvals for
AutoDeploy, this is not a finding.

    From the Tomcat server run the following OS command:

    sudo cat $CATALINA_BASE/conf/server.xml | grep -i -C2 autodeploy

    If the command returns no results, this is not a finding.

    Review the results for the autoDeploy parameter in each Host element.

    <Host name=\"YOUR HOST NAME\" appbase=\"webapps\" unpackWARs=\"true\"
autoDeploy=\"false\">

    If autoDeploy =\"true\", this is a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user, edit the
$CATALINA_BASE/conf/server.xml file.

    Examine each $Host </Host> element, if the element contains
autoDeploy=\"true\", modify the statement to read \", autoDeploy=\"false\".

    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-102495'
  tag rid: 'SV-111437r1_rule'
  tag stig_id: 'TCAT-AS-000540'
  tag fix_id: 'F-108029r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
  auto_deploy = tomcat_server_file["//Host/@autoDeploy"]
  
  describe "The autoDeploy parameter must be set to false" do 
    subject { auto_deploy }
    it { should_not include "true" } 
  end 

end

