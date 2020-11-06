# encoding: UTF-8

control 'V-CIS225' do
  title 'The Remote Listener is Empty.'
  desc  "The remote_listener setting determines whether or not a valid listener can be established on a system separate from the database instance."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

      select value from v$parameter where name = 'remote_listener';

    If the returned value is not EMPTY or not documented in the System Security
Plan as required, this is a finding.
  "
  desc  'fix', "
    Document remote Remote Listener in the System Security Plan.

    From SQL*Plus:

      alter system set remote_listener = '' scope = spfile;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'V-CIS225'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']
  
sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

parameter = sql.query("SELECT UPPER(VALUE) FROM V$SYSTEM_PARAMETER WHERE UPPER(NAME)='REMOTE_LISTENER';")
#.column('uppervalue')    

describe 'REMOTE LISTENERS' do
        subject { parameter }
#	it {should match ''}
	it {should be_empty}
        end
end

