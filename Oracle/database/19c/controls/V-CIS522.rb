# encoding: UTF-8

control 'V-CIS522' do
  title  'DBA_SYS_PRIVS.% Is Revoked from Unauthorized GRANTEE with ADMIN_OPTION '
  desc  "The Oracle database WITH_ADMIN privilege allows the designated user to grant another user the same privileges.  Unauthorized grantees should not have that privilege."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

   SELECT GRANTEE, PRIVILEGE FROM CDB_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');

  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE <privilege> FROM <grantee>; 

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS522'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("SELECT GRANTEE,PRIVILEGE FROM CDB_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');") 

 describe 'DBA SYS' do
 subject { parameter }                      
 it {should be_empty}
        end
end

