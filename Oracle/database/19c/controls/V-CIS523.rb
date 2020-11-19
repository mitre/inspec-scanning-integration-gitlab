# encoding: UTF-8

control 'V-CIS523' do
  title  'Remove unneeded EXECUTIVE ANY PROCEDURE privileges from OUTLN'
  desc  "Migrated OUTLN users have more privileges than required"
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

   SELECT GRANTEE, PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ANY PROCEDURE' AND GRANTEE='OUTLN';
  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE EXECUTE ANY PROCEDURE FROM OUTLN; 3

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS523'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT GRANTEE,PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ANY PROCEDURE' AND GRANTEE='OUTLN';")

 describe 'OUTLN' do
 subject { parameter }                    
 it {should be_empty}
 end
end

