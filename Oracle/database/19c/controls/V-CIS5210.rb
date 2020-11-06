# encoding: UTF-8

control 'V-CIS5210' do
  title  'CREATE PROCEDURE Is Revoked from Unauthorized GRANTEE'
  desc  "The Oracle database CREATE PROCEDURE privilege allows the designated user to create a store procedure that will fire when given teh correct command sequence.  Unauthorized grantees should not have that privilege."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

  SELECT GRANTEE, PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='CREATE PROCEDURE' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE CREATE PROCEDURE FROM <grantee>;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS5210'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

    sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

    parameter = sql.query("SELECT GRANTEE,PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='CREATE PROCEDURE' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');") 

 describe 'CPRO' do
 subject { parameter }                          
 it {should be_empty}
 end
end

