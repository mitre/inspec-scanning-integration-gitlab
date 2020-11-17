# encoding: UTF-8

control 'V-CIS615' do
  title  'DATABASE LINK Audit Option Is Enabled'
  desc  "Enabling the audit option for the DATABASE LINK object causes all activities on database links to be audited."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

   SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS  WHERE USER_NAME IS NULL  AND PROXY_NAME IS NULL  AND SUCCESS = 'BY ACCESS'  AND FAILURE = 'BY ACCESS'  AND AUDIT_OPTION='DATABASE LINK';
  "
  desc  'fix', "
      From SQL*Plus:

	AUDIT DATABASE LINK;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS615'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS' AND AUDIT_OPTION='DATABASE LINK';").column('audit_option')

describe 'DLAI' do
subject { parameter }                          
it {should_not be_empty}
end
end
