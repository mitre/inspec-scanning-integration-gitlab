# encoding: UTF-8

control 'V-CIS45' do
  title 'SYS.USER$MIG Has Been Dropped.'
  desc  "The table sys.user$mig is created during migration and contains the Oracle
	password hashes before the migration starts.  This table should be dropped."
  desc  'rationale', 'The table sys.user$mig is not deleted after the migration. An attacker could access the
  table containing the Oracle password hashes.'
  desc  'check', "
    From SQL*Plus:

    SELECT OWNER, TABLE_NAME,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
    1,(SELECT NAME FROM V$DATABASE),
    (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_TABLES A
    WHERE TABLE_NAME='USER$MIG' AND OWNER='SYS';

    If the returned value is not FALSE or not documented in the System Security
    Plan as required, this is a finding.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in mind if this is
    granted in both container and pluggable database, you must connect to both places to
    revoke.
  
    From SQL*Plus:
    
    DROP TABLE SYS.USER$MIG;

  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS45'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  user_mig = sql.query("
  SELECT OWNER, TABLE_NAME,
  DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
  1,(SELECT NAME FROM V$DATABASE),
  (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
  FROM CDB_TABLES A
  WHERE TABLE_NAME='USER$MIG' AND OWNER='SYS';")

  describe 'Ensure SYS.USER$MIG table has been dropped.' do
    subject { user_mig }           
	  it {should be_empty}
  end

end
