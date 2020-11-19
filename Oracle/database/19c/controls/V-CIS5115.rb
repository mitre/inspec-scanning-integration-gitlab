# encoding: UTF-8

control 'V-CIS5115' do
  title 'EXECUTE is revoked from PUBLIC on "Job Scheduler" Packages'
  desc  "Oracle Database PL/SQL Job Scheduler packages provide APIs to schedule jobs.  The user PUBLIC should not be able to execute these packages."
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
  AND TABLE_NAME IN ('DBMS_SCHEDULER','DBMS_JOB')
  ORDER BY CON_ID, TABLE_NAME;

If the returned value is not FALSE or not documented in the System Security
Plan as required, this is a finding.
  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE EXECUTE ON DBMS_JOB FROM PUBLIC; 
	REVOKE EXECUTE ON DBMS_SCHEDULER FROM PUBLIC;  

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS5115'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  
  job_scheduler_packages = sql.query("
  SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
  V$DATABASE),
  1,(SELECT NAME FROM V$DATABASE),
  (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
  FROM CDB_TAB_PRIVS A
  WHERE GRANTEE='PUBLIC'
  AND PRIVILEGE='EXECUTE'
  AND TABLE_NAME IN ('DBMS_SCHEDULER','DBMS_JOB')
  ORDER BY CON_ID, TABLE_NAME;").column('table_name')

  describe 'Public should not be able to EXECUTE job scheduler packages' do
    subject { job_scheduler_packages }
    it {should be_empty}
  end
  
end

