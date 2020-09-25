control 'V-81915' do
  title "MongoDB must prohibit the use of cached authenticators after an
  organization-defined time period."
  desc "If cached authentication information is out-of-date, the validity of
  the authentication information may be questionable."
  impact 0.5
  tag "gtitle": 'SRG-APP-000400-DB-000367'
  tag "gid": 'V-81915'
  tag "rid": 'SV-96629r1_rule'
  tag "stig_id": 'MD3X-00-000710'
  tag "fix_id": 'F-88765r1_fix'
  tag "cci": ['CCI-002007']
  tag "nist": ['IA-5', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If MongoDB is configured to authenticate using SASL and
  LDAP/Active Directory check the saslauthd command line options in the system
  boot script that starts saslauthd (the location will be dependent on the
  specific Linux operating system and boot script layout and naming conventions).

  If the \"-t\" option is not set for the \"saslauthd\" process in the system
  boot script, this is a finding.

  If any mongos process is running (a MongoDB shared cluster) the
  \"userCacheInvalidationIntervalSecs\" option can be used to specify the cache
  timeout.

  The default is \"30\" seconds and the minimum is \"1\" second."
  tag "fix": "If MongoDB is configured to authenticate using SASL and
  LDAP/Active Directory modify and restart the saslauthd command line options in
  the system boot script and set the \"-t\" option to the appropriate timeout in
  seconds.

  From the Linux Command line (with root/sudo privs) run the following command to
  restart the saslauthd process after making the change for the \"-t\" parameter:

  systemctl restart saslauthd

  If any mongos process is running (a MongoDB shared cluster) the
  \"userCacheInvalidationIntervalSecs\" option to adjust the timeout in seconds
  can be changed from the default \"30\" seconds.

  This is accomplished by modifying the mongos configuration file (default
  location: /etc/mongos.conf) and then restarting mongos."
  describe 'A manual review is required to ensure MongoDB prohibits the use of cached authenticators after an
  organization-defined time period' do
    skip 'A manual review is required to ensure MongoDB prohibits the use of cached authenticators after an
    organization-defined time period'
  end
end
