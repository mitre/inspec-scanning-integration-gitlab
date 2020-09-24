# encoding: UTF-8

control 'TCAT-AS-000540' do
    title 'Autodeploy must be disabled.'
    desc  '
      Tomcat allows auto-deployment of applications while Tomcat is running. This
    can allow untested or malicious applications to be automatically loaded into
    production. Autodeploy must be disabled in production.
  
      This requirement is NA for test and development systems on non-production
    networks. For DevSecOps application environments, the ISSM may authorize
    autodeploy functions on a production Tomcat system if the mission need
    specifies it and an application security vulnerability testing and assurance
    regimen is included in the DevSecOps process.
    '
    desc  'rationale', ''
    desc  'check', '
      If the Tomcat system is a development or test system on a non-production
    network, this requirement is NA.
  
      If the SSP associated with the Host contains ISSM documented approvals for
    AutoDeploy, this is not a finding.
  
      From the Tomcat server run the following OS command:
  
      sudo cat $CATALINA_HOME/conf/server.xml | grep -i -C2 autodeploy
  
      If the command returns no results, this is not a finding.
  
      Review the results for the autoDeploy parameter in each Host element.
  
      <Host name=\'YOUR HOST NAME\' appbase=\'webapps\' unpackWARs=\'true\'
    autoDeploy=\'false\'>
  
      If autoDeploy =\'true\', this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user, edit the
    $CATALINA_HOME/conf/server.xml file.
  
      Examine each $Host </Host> element, if the element contains
    xpoweredBy=\'true\', modify the statement to read \', xpoweredBy=\'false\'.
  
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000141-AS-000095'
    tag gid: 'TCAT-AS-000540'
    tag rid: 'TCAT-AS-000540_rule'
    tag stig_id: 'TCAT-AS-000540'
    tag fix_id: 'F-TCAT-AS-000540_fix'
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    auto_deploy = tomcat_server_file["//Host/@autoDeploy"]
    if !auto_deploy.empty?
        auto_deploy.each do |item|
            describe item do 
                it { should cmp "false" }
            end 
        end 
    else 
        describe "autoDeploy was not found in server.xml" do 
           skip "audoDeploy was not found in server.xml. Skipping this check."
        end 
    end
    
end