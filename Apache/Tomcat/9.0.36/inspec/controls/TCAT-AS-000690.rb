# encoding: UTF-8

control 'TCAT-AS-000690' do
  title 'LDAP authentication must be secured.'
  desc  'LDAP does not provide encryption by default. This can lead to
  authentication credentials being transmitted across network connections in
  clear text. To address this risk, Tomcat must be configured to use secure LDAP
  (LDAPS).'
  desc  'rationale', ''
  desc  'check', '
    From the Tomcat server as a privileged user, run the following commands:

    sudo grep -i -A8 JNDIRealm $CATALINA_HOME/conf/server.xml

    If the JNDIRealm connectionURL setting is not configured to use LDAPS, if
  it does not exist, or is commented out, this is a finding.  

    EXAMPLE:
    This is an example. Substitute localhost for the LDAP server IP and
  configure other LDAP-related settings as well.

    <Realm   className=\'org.apache.catalina.realm.JNDIRealm\'
    connectionURL=\'ldaps://localhost:686\'
    ...
    />
  '
  desc  'fix', '
    Identify the server IP that is providing LDAP services and configure the
  Tomcat user roles schema within LDAP. Refer to the manager and host-manager
  web.xml files for application specific role information that can be used for
  setting up the roles for those applications. The default location for these
  files is: $CATALINA_HOME/webapps/<AppName>/WEB-INF/web.xml

    From the Tomcat server console as a privileged user, edit the
  $CATALINA_HOME/conf/server.xml file.

    Locate the <Realm> element in the server.xml file, add a nested <Realm>
  element using the JNDIRealm className and configure the associated LDAP
  settings as per the LDAP server connection requirements.

    EXAMPLE:
    This is for illustration purposes only. The user must modify the LDAP
  settings on a case by case basis as per the individual LDAP server and schema.

    <Realm   className=\'org.apache.catalina.realm.JNDIRealm\'
         connectionURL=\'ldaps://localhost:686\'
           userPattern=\'uid={0},ou=people,dc=myunit,dc=mil\'
              roleBase=\'ou=groups,dc=myunit,dc=mil\'
              roleName=\'cn\'
            roleSearch=\'(uniqueMember={0})\'
    />
  '
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag gid: 'TCAT-AS-000690'
  tag rid: 'TCAT-AS-000690_rule'
  tag stig_id: 'TCAT-AS-000690'
  tag fix_id: 'F-TCAT-AS-000690_fix'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

    
    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    realms = tomcat_server_file['//Realm/@className']
    index = 0

    if realms.include? "org.apache.catalina.realm.JNDIRealm"
      for i in 0..realms.count
        if realms[i] == "org.apache.catalina.realm.JNDIRealm"
          break
        else
          index+=1
        end
      end
    end

    connection_url = tomcat_server_file["//Realm[#{index}]/@connectionURL"]
    if !connection_url.empty?
      ldaps = connection_url[0].strip.split(":")[0]
      describe ldaps do 
        it { should cmp "ldaps" }
      end
    else 
      describe connection_url.empty? do 
        it { should  cmp "false" }
      end
    end
end

