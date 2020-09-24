control 'V-81885' do
  title "Database contents must be protected from unauthorized and unintended
  information transfer by enforcement of a data-transfer policy."
  desc "Applications, including DBMSs, must prevent unauthorized and
  unintended information transfer via shared system resources.

    Data used for the development and testing of applications often involves
  copying data from production. It is important that specific procedures exist
  for this process, to include the conditions under which such transfer may take
  place, where the copies may reside, and the rules for ensuring sensitive data
  are not exposed.

      Copies of sensitive data must not be misplaced or left in a temporary
  location without the proper controls.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000243-DB-000128'
  tag "gid": 'V-81885'
  tag "rid": 'SV-96599r1_rule'
  tag "stig_id": 'MD3X-00-000460'
  tag "fix_id": 'F-88735r1_fix'
  tag "cci": ['CCI-001090']
  tag "nist": ['SC-4', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the procedures for the refreshing of development/test
  data from production.

  Review any scripts or code that exists for the movement of production data to
  development/test systems, or to any other location or for any other purpose.

  Verify that copies of production data are not left in unprotected locations.

  If the code that exists for data movement does not comply with the
  organization-defined data transfer policy and/or fails to remove any copies of
  production data from unprotected locations, this is a finding."
  tag "fix": "Modify any code used for moving data from production to
  development/test systems to comply with the organization-defined data transfer
  policy, and to ensure copies of production data are not left in unsecured
  locations."
  describe 'A manual review is required to ensure that database contents are protected from unauthorized and unintended
  information transfer by enforcement of a data-transfer policy.' do
    skip 'A manual review is required to ensure that database contents are protected from unauthorized and unintended
    information transfer by enforcement of a data-transfer policy.'
  end
end