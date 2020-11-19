# encoding: UTF-8

control 'V-CIS5121' do
  title 'EXECUTE is not granted to PUBLIC on Non-default" Packages'
  desc  "Non-Default group of PL/SQL packages, which are not granted to public by default, packages should not be granted to public."
  desc  'rationale', ''
  desc  'check', "

	From SQL*Plus:

   SELECT TABLE_NAME, PRIVILEGE, GRANTEE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME IN ('DBMS_BACKUP_RESTORE','DBMS_FILE_TRANSFER','DBMS_SYS_SQL','DBMS_REPCAT_SQL_U TL','INITJVMAUX', 'DBMS_AQADM_SYS','DBMS_STREAMS_RPC','DBMS_PRVTAQIM','LTADM', 'DBMS_IJOB','DBMS_PDB_EXEC_SQL'); 
  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE EXECUTE ON DBMS_BACKUP_RESTORE FROM PUBLIC; 
	REVOKE EXECUTE ON DBMS_FILE_TRANSFER FROM PUBLIC; 
	REVOKE EXECUTE ON DBMS_SYS_SQL FROM PUBLIC; 
	REVOKE EXECUTE ON DBMS_REPCAT_SQL_UTL FROM PUBLIC; 
	REVOKE EXECUTE ON INITJVMAUX FROM PUBLIC; 
	REVOKE EXECUTE ON DBMS_AQADM_SYS FROM PUBLIC; 
	REVOKE EXECUTE ON DBMS_STREAMS_RPC FROM PUBLIC; 
	REVOKE EXECUTE ON DBMS_PRVTAQIM FROM PUBLIC;                    
	REVOKE EXECUTE ON LTADM FROM PUBLIC;                            
	REVOKE EXECUTE ON DBMS_IJOB FROM PUBLIC;                        
	REVOKE EXECUTE ON DBMS_PDB_EXEC_SQL FROM PUBLIC;   

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS5121'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("SELECT TABLE_NAME, PRIVILEGE, GRANTEE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME IN ('DBMS_BACKUP_RESTORE','DBMS_FILE_TRANSFER','DBMS_SYS_SQL','DBMS_REPCAT_SQL_U TL','INITJVMAUX', 'DBMS_AQADM_SYS','DBMS_STREAMS_RPC','DBMS_PRVTAQIM','LTADM', 'DBMS_IJOB','DBMS_PDB_EXEC_SQL');").column('value')

describe 'DefaultPR' do
subject { parameter }                          
it {should be_empty}
end
end

