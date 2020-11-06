# encoding: UTF-8

control 'V-CIS224' do
  title 'The Oracle OS_ROLES parameter must be set to FALSE.'
  desc  "The OS_ROLES setting permits externally created groups to ve applied to database management.
  Allowing the OS to use external groups for database management could cause privilege overslaps and
  generally waken security."
  desc  'rationale', ''
  desc  'check', "
    From SQL*Plus:

      select value from v$parameter where name = 'os_roles';

    If the returned value is not FALSE or not documented in the System Security
Plan as required, this is a finding.
  "
  desc  'fix', "
    Document remote OS roles in the System Security Plan.

    From SQL*Plus:

      alter system set os_roles = FALSE scope = spfile;

    The above SQL*Plus command will set the parameter to take effect at next
system startup.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-DB-999900'
  tag gid: 'CIS224'
  tag rid: ''
  tag stig_id: 'N/A'
  tag fix_id: ''
  tag cci: ['']
  tag nist: ['CM-6 b']

sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

os_role = sql.query("select value from v$parameter where name = 'os_roles';").column('value')
                         
 describe 'OS_ROLE' do
 subject { os_role }
 it {should cmp 'FALSE'}
 end
end

