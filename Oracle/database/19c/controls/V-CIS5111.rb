 # encoding: UTF-8

control 'V-CIS5111' do
  title 'Execute Is Revoked From Public On Network Package.'
  desc  "As described below, Oracle Database PL/SQL Network packages -DBMS_LDAP, UTL_INADDR, UTL_TCP, UTL_MAIL, UTL_SMTP, UTL_DBWS, UTL_ORAMTS, UTL_HTTPand type HTTPURITYPEprovide PL/SQL APIs to interact or access remote servers. The PUBLIC should not be able to execute these packages."  
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

   SELECT TABLE_NAME, PRIVILEGE, GRANTEEFROM DBA_TAB_PRIVS
   WHERE GRANTEE='PUBLIC'
   AND PRIVILEGE='EXECUTE'
   AND TABLE_NAME IN ('DBMS_LDAP','UTL_INADDR','UTL_TCP','UTL_MAIL','UTL_SMTP','UTL_DBWS','UTL_ORAMTS','UTL_HTTP','HTTPURITYPE');

    If the returned value is not FALSE or not documented in the System Security
Plan as required, this is a finding.
  "
  desc  'fix', "
    Document in the System Security Plan.

    If not required, disable use of remote OS roles.

    From SQL*Plus:

      REVOKE EXECUTE ON DBMS_LDAP FROM PUBLIC;
      REVOKE EXECUTE ON UTL_INADDR FROM PUBLIC;
      REVOKE EXECUTE ON UTL_TCP FROM PUBLIC;
      REVOKE EXECUTE ON UTL_MAIL FROM PUBLIC;
      REVOKE EXECUTE ON UTL_SMTP FROM PUBLIC;
      REVOKE EXECUTE ON UTL_DBWS FROM PUBLIC;
      REVOKE EXECUTE ON UTL_ORAMTS FROM PUBLIC;
      REVOKE EXECUTE ON UTL_HTTP FROM PUBLIC;
      REVOKE EXECUTE ON HTTPURITYPE FROM PUBLIC;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS5111'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  public_network_packages = sql.query("SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
  V$DATABASE),
  1,(SELECT NAME FROM V$DATABASE),
  (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
  FROM CDB_TAB_PRIVS A
  WHERE GRANTEE='PUBLIC'
  AND PRIVILEGE='EXECUTE'
  AND TABLE_NAME IN
  ('DBMS_LDAP','UTL_INADDR','UTL_TCP','UTL_MAIL','UTL_SMTP','UTL_DBWS','UTL_ORA
  MTS','UTL_HTTP','HTTPURITYPE')
  ORDER BY CON_ID, TABLE_NAME;").column('table_name')

  describe 'Public should not be able to EXECUTE network packages' do
    subject { public_network_packages }
    it {should be_empty}
  end

end

