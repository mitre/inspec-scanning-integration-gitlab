# encoding: UTF-8

control 'V-CIS618' do
  title 'The SYNONYM Audit Option Is Enabled'
  desc  "The SYNONYM object allows for the creation of an alternate description of an object such as a Java class schema object, materialized veiw, operator, package, procedure, sequence, stored function, table, view, user-defined object type, or even another synonym.  This synonym puts a dependency on its target and is rendered invalid if the target object is changed/dropped.  Enabling the audit option causes all user activities involving the creation or dropping of public synonym to be audited."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

  SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='SYNONYM'; 
  "
  desc  'fix', "
      From SQL*Plus:

	AUDIT SYNONYM;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS618'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS' AND AUDIT_OPTION='SYNONYM';")

describe 'SAO' do
subject { parameter }                         
it {should_not be_empty}
end
end
