# encoding: UTF-8

control 'TCAT-AS-000530' do
    title 'The deployXML attribute must be set to false in hosted environments.'
    desc  '
      The Host element controls deployment. Automatic deployment allows for
    simpler management, but also makes it easier for an attacker to deploy a
    malicious application. Automatic deployment is controlled by the autoDeploy and
    deployOnStartup attributes. If both are false, only Contexts defined in
    server.xml will be deployed, and any changes will require a Tomcat restart.
  
      In a hosted environment where web applications may not be trusted, set the
    deployXML attribute to false to ignore any context.xml packaged with the web
    application that may try to assign increased privileges to the web application.
    Note that if the security manager is enabled that the deployXML attribute will
    default to false.
  
      This requirement is NA for test and development systems on non-production
    networks. For DevSecOps application environments, the ISSM may authorize
    autodeploy functions on a production Tomcat system if the mission need
    specifies it and an application security vulnerability testing and assurance
    regimen is included in the DevSecOps process.
    '
    desc  'rationale', ''
    desc  'check', '
      This requirement is NA for test and development systems on non-production
    networks. For production application environments, the ISSM may authorize
    autodeploy functions on a production Tomcat system if the mission need
    specifies it and an application security vulnerability testing and assurance
    regimen is included in the DevSecOps process or other application development
    processes and satisfactory results from the latest vulnerability testing are
    provided to the inspector during readiness review.
  
      From the Tomcat server as a privileged user:
  
      sudo grep -i deployXML $CATALINA_HOME/conf/server.xml
  
      If the deployXML setting is configured as true and there is no documented
    authorization to allow automatic deployment of applications, this is a finding.
    '
    desc  'fix', '
      Document authorization for application auto deployment in the System
    Security Plan (SSP).
  
      From the Tomcat server as a privileged user, edit the
    $CATALINA_HOME/conf/server.xml file.
  
      sudo nano $CATALINA_HOME/conf/server.xml
  
      Locate each <host> element in the server xml file and if the
    deployXML=\'true\' ensure each host is authorized for application auto
    deployment and document the authorization in the system security plan. If
    authorization is not provided, set the deployXML=\'false\'
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000141-AS-000095'
    tag gid: 'TCAT-AS-000530'
    tag rid: 'TCAT-AS-000530_rule'
    tag stig_id: 'TCAT-AS-000530'
    tag fix_id: 'F-TCAT-AS-000530_fix'
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']
    
    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    deploy_xml = tomcat_server_file["//Host/@deployXML"]
    if !deploy_xml.empty?
        deploy_xml.each do |item|
            describe item do 
                it { should cmp "false" }
            end 
        end 
    else 
        describe "deployXML was not found in server.xml" do 
           skip "deployXML was not found in server.xml. Skipping this check."
        end 
    end

end