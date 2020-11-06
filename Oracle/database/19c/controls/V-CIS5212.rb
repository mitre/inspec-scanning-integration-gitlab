# encoding: UTF-8

control 'V-CIS5212' do
  title  'CREATE ANY LIBRARY Is Revoked from Unauthorized GRANTEE'
  desc  "The Oracle database CREATE ANY LIBRARY privilege allows the designated user to create objects at are associated to the shared libraries.  Unauthorized grantees should not have that privilege."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

  SELECT GRANTEE, PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='CREATE ANY LIBRARY' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE CREATE ANY LIBRARY FROM <grantee>;
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS5212'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']
 
 sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

 parameter = sql.query("SELECT GRANTEE,PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='CREATE ANY LIBRARY' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');")

 describe 'CAL' do
 subject { parameter }
 it {should be_empty}
 end
end

