# encoding: UTF-8

control 'V-102547' do
  title "LockOutRealms lockOutTime attribute must be set to 600 seconds (10
minutes) for admin users."
  desc  "A LockOutRealm adds the ability to specify a lockout time that
prevents further attempts after multiple failed logins. Setting the lockOutTime
attribute to 600 will lock out a user account for 10 minutes. Further
authentication failures during the lock out time will cause the lock out timer
to reset to zero, effectively extending the lockout time. Valid authentication
attempts during the lockout period will not succeed but will also not reset the
lockout time.

    LockOutRealm is an implementation of the Tomcat Realm interface that
extends the CombinedRealm to provide user lock out functionality if there are
too many failed authentication attempts in a given period of time. A
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

    If there are no results or if the LockOutRealm lockOutTime setting is not
configured to 600 (10 minutes), this is a finding.
  "
  desc  'fix', "
    From the Tomcat server console as a privileged user, edit the
$CATALINA_BASE/conf/server.xml file.

    sudo nano $CATALINA_BASE/conf/server.xml file

    Locate or add the LockOutRealm element. Set lockOutTime=\"600\"

    EXAMPLE:
          <Realm className=\"org.apache.catalina.realm.LockOutRealm\"
failureCount=\"5\" lockOutTime=\"600\">
    ...
    </Realm>
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000316-AS-000199'
  tag gid: 'V-102547'
  tag rid: 'SV-111487r1_rule'
  tag stig_id: 'TCAT-AS-001040'
  tag fix_id: 'F-108079r1_fix'
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']

  catalina_base = input('catalina_base', value: '/usr/local/tomcat')
  tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
  lockout_time = tomcat_server_file["//Realm/@lockOutTime"]

  describe "The lock out time period for the LockoutRealm configuration must be set to 600 seconds" do 
    subject { lockout_time }
    it { should cmp "600" } 
  end

end