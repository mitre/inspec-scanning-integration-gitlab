# encoding: UTF-8

control 'V-CIS613' do
  title  'SYSTEM GRANT Audit Option Is Enabled'
  desc  "Enabling the audit option for the SYSTEM GRANT object causes auditing of any attempt, successful or not, to grant or revoke any system privilege or role, regardless of privilege held by the user attempting the operation."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

   SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='SYSTEM GRANT';
  "
  desc  'fix', "
      From SQL*Plus:

	AUDIT SYSTEM GRANT;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS613'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS' AND AUDIT_OPTION='SYSTEM GRANT';").column('audit_option')
 
describe 'SGAO' do
subject { parameter }                       
it {should_not be_empty}
end
end

