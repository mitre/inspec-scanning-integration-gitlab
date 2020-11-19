# encoding: UTF-8

control 'V-CIS531' do
  title  'SELECT_CATALOG_ROLE Is Revoked from Unauthorized GRANTEE'
  desc  "The Oracle database SELECT_CATALOG_ROLE proivdes SELECT privileges on all data dictionary views held in the SYS schema.  Unauthorized grantees should not have that role."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

  SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='SELECT_CATALOG_ROLE' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y'); 

  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE SELECT_CATALOG_ROLE FROM <grantee>;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS531'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT GRANTEE,GRANTED_ROLE FROM CDB_ROLE_PRIVS WHERE GRANTED_ROLE='SELECT_CATALOG_ROLE' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y') AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');") 

describe 'SCROLE' do
subject { parameter }                         
it {should be_empty}
end
end

