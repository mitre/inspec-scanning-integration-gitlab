# encoding: UTF-8

control 'V-102543' do
  title 'LockOutRealms must be used for management of Tomcat.'
  desc  "A LockOutRealm adds the ability to lock a user out after multiple
failed logins. LockOutRealm is an implementation of the Tomcat Realm interface
that extends the CombinedRealm to provide user lock out functionality if there
are too many failed authentication attempts in a given period of time. A
LockOutRealm is created by wrapping around a standard realm such as a JNDI
Directory Realm which connects Tomcat to an LDAP Directory.

    A Catalina container (Engine, Host, or Context) may contain no more than
one Realm element (although this one Realm may itself contain multiple nested
Realms). In addition, the Realm associated with an Engine or a Host is
automatically inherited by lower-level containers unless the lower level
container explicitly defines its own Realm. If no Realm is configured for the
Engine, an instance of the Null Realm will be configured for the Engine
automatically.
  "
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server console, run the following command:

    sudo grep -i  LockOutRealm $CATALINA_BASE/conf/server.xml.

    If there are no results or if the LockOutRealm is not used for the Tomcat
management application context, this is a finding.
  "
  desc  'fix', "
    From the Tomcat server console as a privileged user edit the
$CATALINA_BASE/conf/server.xml file.

    sudo nano $CATALINA_BASE/conf/server.xml file

    Locate or add the LockOutRealm element. Make sure the LockOutRealm element
is applied to the management application at a minimum (if the management
application is in use on the system). This is done by ensuring the LockOutRealm
is nested under the Engine, Host or directly within the management application
Context container.

    EXAMPLE:

          <Realm className=\"org.apache.catalina.realm.LockOutRealm\"
failureCount=\"5\" lockOutTime=\"600\">
    ...
    </Realm>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag gid: 'V-102543'
  tag rid: 'SV-111483r1_rule'
  tag stig_id: 'TCAT-AS-001020'
  tag fix_id: 'F-108075r1_fix'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
  realms = tomcat_server_file["//Realm/@className"]
    
  describe "The LockOutRealm must be defined" do 
    subject { realms } 
    it { should include "org.apache.catalina.realm.LockOutRealm" }
  end

end

