# encoding: UTF-8

control 'TCAT-AS-000710' do
    title 'Keystore file must be protected.'
    desc  '
      Keystore file contains authentication information used to access
    application data and data resources. Access to the file must be protected.
  
      The default location is in the .keystore file stored in the home folder of
    the user account used to run Tomcat although some administrators may choose to
    locate the file elsewhere. The location will also be specified in the
    server.xml file.
    '
    desc  'rationale', ''
    desc  'check', '
      Identify the location of the .keystore file. Refer to system documentation
    or review the server.xml file for a specified .keystore file location.
  
      From the Tomcat server console run the following command to check the
    server.xml file:
  
      sudo grep -i keystorefile $CATALINA_HOME/conf/server.xml
  
      Extract the location of the file from the output.
  
      Example:
      [keystorefile=/opt/tomcat/conf/<filename.jks>]
  
      sudo ls -la [keystorefile location]
  
      If the file permissions are not set to 640 USER:root GROUP:tomcat, this is
    a finding.
  
      If the keystore file is not stored within the tomcat folder path, i.e.
    [/opt/tomcat/], this is a finding.
    '
    desc  'fix', '
      Run the following commands on the Tomcat server:
  
      sudo chmod 640 [keystorefile]
      sudo chown root [keystorefile]
      sudo chgrp tomcat [keystorefile]
  
      Store the keystore file in a secured folder, preferably within the Tomcat
    folder path.
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000176-AS-000125'
    tag gid: 'TCAT-AS-000710'
    tag rid: 'TCAT-AS-000710_rule'
    tag stig_id: 'TCAT-AS-000710'
    tag fix_id: 'F-TCAT-AS-000710_fix'
    tag cci: ['CCI-000186']
    tag nist: ['IA-5 (2) (b)']
    
    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    keystore_file=tomcat_server_file["//Connector/@keystoreFile"]

    if file(keystore_file[0]).exist?

        keystore_dir=keystore_file[0].split('/').slice(0,3).join('/')
    
        describe keystore_dir do 
            it { should cmp "/opt/tomcat" }
        end

        describe file(keystore_file[0]) do 
            its('mode') { should cmp '640' }
            its('owner') { should cmp 'root' }
            its('group') { should cmp 'tomcat' }
        end
    else
        describe file(keystore_file).exist? do 
            it { should cmp "true" }
        end
    end
    
end