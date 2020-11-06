# encoding: UTF-8

control 'V-CIS617' do
  title 'The PUBLIC SYNONYM Audit Option Is Enabled'
  desc  "The PUBLIC SYNONYM object allows for the creation of an alternate description of an object.  Public synonyms are accessible by all users that have the appriate privileges to the underlying object.  Enabling the audit option causes all user activities involving the creation or dropping of public synonym to be audited."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

  SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='PUBLIC SYNONYM';
  "
  desc  'fix', "
      From SQL*Plus:

	AUDIT PUBLIC SYNONYM;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7   
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS617'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS' AND AUDIT_OPTION='PUBLIC SYNONYM';")

describe 'TPS' do
subject { parameter }
it {should_not be_empty}
end
end
