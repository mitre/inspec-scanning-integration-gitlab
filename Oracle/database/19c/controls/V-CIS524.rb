# encoding: UTF-8

control 'V-CIS524' do
  title  'EXECUTE ANY PROCEDURE Is Revoked from DBSNMP'
  desc  "Remove uneeded EXECUTE ANY PROCEDURE privileges from DBSNMP."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

   SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ANY PROCEDURE' AND GRANTEE='DBSNMP';
  "
  desc  'fix', "
      From SQL*Plus:

	REVOKE EXECUTE ANY PROCEDURE FROM DBSNMP; 

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'V-CIS524'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("SELECT GRANTEE,PRIVILEGE FROM CDB_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ANY PROCEDURE' AND GRANTEE='DBSNMP';")
 
  describe 'DBSMP' do
  subject { parameter }                   
  it {should be_empty}
  end
end

