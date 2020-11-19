# encoding: UTF-8

control 'V-CIS43' do
  title 'DBA_USERS.AUTHENTICATION_TYPE Not Set To External For Any User.'
  desc  "The authentication_type='EXTERNAL' setting determines whether or not a user can be
authenticated by a remote OS to allow access tot he database with full authorization.  This setting should not be use."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

      select username from dba_users where authentication_type = external;
  "
  desc  'fix', "
    Document DBA_USERS.Authentication_Typeremote OS roles in the System Security Plan.

    From SQL*Plus:

      ALTER USER <username> IDENTIFIED BY <password>; 

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS43'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

    sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

    parameter = sql.query("select username from dba_users where authentication_type = 'EXTERNAL';").column('value')
                          
        describe 'ATYPE' do
        subject { parameter }
	it {should be_empty}
        end
end

