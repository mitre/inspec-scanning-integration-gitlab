# encoding: UTF-8

control 'V-CIS5112' do
  title 'EXECUTE is revoked from PUBLIC on File System Packages'
  desc  "Oracle Database PL/SQL packages - DMS_ADVISOR, DMS_LOB and UTL_FILE - provide APIs to access files on the server.  The user PUBLIC should not be able to execute these packages."
  desc  'rationale', ''
  desc  'check', "

	From SQL*Plus:
  
  SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
  V$DATABASE),
  1,(SELECT NAME FROM V$DATABASE),
  (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
  FROM CDB_TAB_PRIVS A
  WHERE GRANTEE='PUBLIC'
  AND PRIVILEGE='EXECUTE'
  AND TABLE_NAME IN ('DBMS_ADVISOR','DBMS_LOB','UTL_FILE')
  ORDER BY CON_ID, TABLE_NAME;

If the returned value is not FALSE or not documented in the System Security
Plan as required, this is a finding.
  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE EXECUTE ON DBMS_ADVISOR FROM FROM PUBLIC; 
	REVOKE EXECUTE ON DBMS_LOB FROM PUBLIC; 
	REVOKE EXECUTE ON UTIL_FILE FROM PUBLIC

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS5112'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  file_system_packages = sql.query("SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
  V$DATABASE),
  1,(SELECT NAME FROM V$DATABASE),
  (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
  FROM CDB_TAB_PRIVS A
  WHERE GRANTEE='PUBLIC'
  AND PRIVILEGE='EXECUTE'
  AND TABLE_NAME IN ('DBMS_ADVISOR','DBMS_LOB','UTL_FILE')
  ORDER BY CON_ID, TABLE_NAME;").column('table_name')

  describe 'Public should not be able to EXECUTE file system packages' do
    subject { file_system_packages }
    it {should be_empty}
  end
end

