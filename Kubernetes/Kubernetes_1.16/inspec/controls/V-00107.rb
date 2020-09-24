# encoding: UTF-8

control 'V-00107' do
    title 'For accounts using password authentication, the application must store only cryptographic representations of passwords.'
    desc  "Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read and easily compromised. Use of passwords for authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication. 
	Examples of situations where a user ID and password might be used include:
	- When the user does not use a CAC and is not a current DoD employee, member of the military, or DoD contractor.
	- When a user has been officially designated as temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) (i.e., Temporary Exception User) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.
	- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.
	If the password is already encrypted and not a plaintext password, this meets this requirement. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption. This method uses a one-way hashing encryption algorithm with a salt value to validate a user's password without having to store the actual password. Performance and time required to access are factors that must be considered, and the one-way hash is the most feasible means of securing the password and providing an acceptable measure of password security.
	Verifying the user knows a password is performed using a password verifier. In its simplest form, a password verifier is a computational function that is capable of creating a hash of a password and determining if the value provided by the user matches the hash. A more secure version of verifying a user knowing a password is to store the result of an iterating hash function and a large random salt value as follows:
	H0 = H(pwd, H(salt))
    Hn = H(Hn-1,H(salt))
	In the above, \"n\" is a cryptographically-strong random [*3] number. \"Hn\" is stored along with the salt. When the application wishes to verify that the user knows a password, it simply repeats the process and compares \"Hn\" with the stored \"Hn\". A salt is essentially a fixed-length cryptographically strong random value.
	Another method is using a keyed-hash message authentication code (HMAC). HMAC calculates a message authentication code via a cryptographic hash function used in conjunction with an encryption key. The key must be protected as with any private key.
	This requirement applies to all accounts including authentication server, AAA, and local account, including the root account and the account of last resort."
    desc  'rationale', ''
    desc  'check', "On the Kubernetes Master node, run the following command:
	kubectl get all -o jsonpath='{range .items[?(@..secretKeyRef)]} {.kind} {.metadata.name} {\"\n\"}{end}' -A
	If any of the values returned reference environment variables, this is a finding."
    desc  'fix', "Any secrets stored as environment variables must be moved to be secret files with the proper protections and enforcements or placed within a password vault."
    impact 0.7
    tag severity: 'high'
    tag gtitle: 'SRG-APP-000171'
    tag gid: 'V-00107'
    tag rid: ''
    tag stig_id: 'SRG-APP-000171'
    tag fix_id: ''
    tag cci: ['CCI-000196']
    tag nist: ['IA-5 (1) (c)']

    describe bash('sudo kubectl get all -o jsonpath=\'{range .items[?(@..secretKeyRef)]} {.kind} {.metadata.name} {"\n"}{end}\' -A') do
        its('stdout') { should be_empty }
    end
end

# kubectl get all -o jsonpath='{range .items[?(@..secretKeyRef)]} {.kind} {.metadata.name} {"\n"}{end}' -A