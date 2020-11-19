# encoding: UTF-8

control 'V-CIS5133' do
  title 'ALL Is Revoked on Sensitive Tables'
  desc  "Access	to sensitive information such as hashed passwords may allow unauthorized users to decrypt the passwords"
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

   SELECT GRANTEE, PRIVILEGE, TABLE_NAME FROM DBA_TAB_PRIVS WHERE TABLE_NAME in ('CDB_LOCAL_ADMINAUTH$','DEFAULT_PWD$','ENC$','HISTGRM$','HIST_HEAD$','LINK$' ,'PDB_SYNC$','SCHEDULER$_CREDENTIAL','USER$','USER_HISTORY$','XS$VERIFIERS') AND OWNER = 'SYS' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') ORDER BY CON_ID, TABLE_NAME;
  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE ALL ON SYS.CDB_LOCAL_ADMINAUTH$ FROM <grantee>; 
	REVOKE ALL ON SYS.DEFAULT_PWD$ FROM <grantee>; 
	REVOKE ALL ON SYS.ENC$ FROM <grantee>; 
	REVOKE ALL ON SYS.HISTGRM$ FROM <grantee>; 
	REVOKE ALL ON SYS.HIST_HEAD$ FROM <grantee>; 
	REVOKE ALL ON SYS.LINK$ FROM <grantee>; 
	REVOKE ALL ON SYS.PDB_SYNC$ FROM <grantee>; 
	REVOKE ALL ON SYS.SCHEDULER$_CREDENTIAL FROM <grantee>; 
	REVOKE ALL ON SYS.USER$ FROM <grantee>; 
	REVOKE ALL ON SYS.USER_HISTORY$ FROM <grantee>; 
	REVOKE ALL ON SYS.XS$VERIFIERS FROM <grantee>; 

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS5133'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT GRANTEE,PRIVILEGE,TABLE_NAME FROM CDB_TAB_PRIVS WHERE TABLE_NAME IN ('CDB_LOCAL_ADMINAUTH$','DEFAULT_PWD$','ENC$','HIST_HEAD$','LINK$','PDB_SYNC$','SCHEDULER$_CREDENTIAL','USER$','USER_HISTORY$','XS$VERIFIERS') AND OWNER= 'SYS' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') ORDER BY CON_ID, TABLE_NAME;")

describe 'Sens' do
subject { parameter }                          
it {should be_empty}
end
end

