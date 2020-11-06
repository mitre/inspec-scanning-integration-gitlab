# encoding: UTF-8

control 'V-CIS6114' do
  title 'Ensure the ALL Audit Option on SYS.AUD$ is Enabled.'
  desc  "The logging of attempt to alter the audit trail in the SYS.AUD$ table will provide a record of any actibities that may indicate unauthorized attempts to access the audit trail.  Enabling the audit option will cause these activities to be audited."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

	SELECT * FROM CDB_OBJ_AUDIT_OPTS WHERE OBJECT_NAME='AUD$' AND ALT='A/A' AND AUD='A/A' AND COM='A/A' AND DEL='A/A' AND GRA='A/A' AND IND='A/A' AND INS='A/A' AND LOC='A/A' AND REN='A/A' AND SEL='A/A' AND UPD='A/A' AND FBK='A/A';    

 "
  desc  'fix', "
      From SQL*Plus:

	AUDIT ALL ON SYS.AUD$ BY ACCESS; 

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS6114'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  
  audit_options = sql.query("
  SELECT *
  FROM CDB_OBJ_AUDIT_OPTS
  WHERE OBJECT_NAME='AUD$'
  AND ALT='A/A'
  AND AUD='A/A'
  AND COM='A/A'
  AND DEL='A/A'
  AND GRA='A/A'
  AND IND='A/A'
  AND INS='A/A'
  AND LOC='A/A'
  AND REN='A/A'
  AND SEL='A/A'
  AND UPD='A/A'
  AND FBK='A/A';").column('OBJECT_NAME')

  describe 'Ensure ALL audit option is enabled on AUD$ system packages' do
    subject { audit_options }
    it {should_not be_empty}
  end
end
