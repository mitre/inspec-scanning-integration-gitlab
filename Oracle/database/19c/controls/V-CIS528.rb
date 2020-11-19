# encoding: UTF-8

control 'V-CIS528' do
  title  ' EXEMPT ACCESS POLICY Is Revoked from Unauthorized GRANTEE'
  desc  "The Oracle database EXEMPT AUDIT POLICY keywork provides the suer the capability to access all the table rows regardless of row-level security lockout.  Unauthorized grantees should not have that keyword assinged to them."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

  SELECT GRANTEE, PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='EXEMPT ACCESS POLICY' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
 "
  desc  'fix', "
      From SQL*Plus:

	REVOKE EXEMPT ACCESS POLICY FROM <grantee>;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS528'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

    sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

    parameter = sql.query("SELECT GRANTEE,PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='EXEMPT ACCESS POLICY' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');")
    
 describe 'EAP' do
 subject { parameter }
 it {should be_empty}
 end
end

