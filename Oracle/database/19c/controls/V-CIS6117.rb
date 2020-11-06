# encoding: UTF-8

control 'V-CIS6117' do
  title 'The TRIGGER Audit Option Is Enabled'
  desc  "TRIGGER may be used to modify DML actions or invoke other actions when some types of user-initiated actions occur.  Enabling this audit option will cause auditing of any attempt, successful or not to create, drop, enable or disable any schema trigger in any schema regardless of privilege or lack thereof.  For enabling and disabling a trigger, it covers both ALTER TRIGGER and ALTER TABLE."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

	SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM DBA_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='TRIGGER';

    "
  desc  'fix', "
      From SQL*Plus:

	AUDIT TRIGGER;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS6117'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL
			AND PROXY_NAME IS NULL
			AND SUCCESS = 'BY ACCESS'
			AND FAILURE = 'BY ACCESS'
			AND AUDIT_OPTION='TRIGGER';")
                         
describe 'TAO' do
subject { parameter }
it {should_not be_empty}
end
end
