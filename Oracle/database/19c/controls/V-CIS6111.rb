# encoding: UTF-8

control 'V-CIS6111' do
  title 'The GRANT ANY OBJECT PRIVILEGE Audit Option Is Enabled'
  desc  "GRANT ANY OBJECT PRIVILEGE allows the user to grant or revoke any object privilege, which includes privileges on tables, directories, mining models, etc.  Enabling the audit option causes auditing of all uses of that privilege."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

  SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='GRANT ANY OBJECT PRIVILEGE'; 
  "
  desc  'fix', "
      From SQL*Plus:

	AUDIT GRANT ANY OBJECT PRIVILEGE;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS6111'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS' AND AUDIT_OPTION='GRANT ANY OBJECT PRIVILEGE';")

describe 'GAOP' do
subject { parameter }                          
it {should_not be_empty}
end
end
