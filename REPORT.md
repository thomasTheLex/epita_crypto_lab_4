# Lab 4 report

Answer from **your** build: every claim points to a file in this repository or to a line in `evidence/`.

## 1. Inventory

Every key and certificate you created: what it is, algorithm and size, where the key lives, who can read it,
validity, what it is used for.

| Item | Key location | Readable by | Valid until | Purpose |
|---|---|---|---|---|
| root CA, EC P-384, self-signed, `root/certs/ca.cert.pem` | `root/private/ca.key.pem`, encrypted (AES-256, passphrase) | the `root-ca` container (no network); on the host, my user account, but only I know the passphrase | 2046-11-11, 20 years (`openssl x509 -noout -enddate`) | signs the intermediate and the root CRL, nothing else; stopped the rest of the time |
| intermediate (issuing) CA, EC P-384, signed by root CA, `intermediate/certs/int.cert.pem` | `intermediate/private/ca.key.pem`, encrypted (AES-256, passphrase) | le conteneur `issuing-ca`, mon utilisateur mais uniquement si je connais la passphrase | 2036-11-14, 10 ans | signe les certificats clients et serveurs |

**Lifetimes.** The root lasts 20 years, the intermediate 10, the server and client certificates 90 days.
Justify each number: what would a shorter or a longer lifetime cost you? Why 90 days for the server, and not
1 year, or 7 days?
La CA root a une durée de vie de 20 ans car il va servir à signé la CA intermédiaire, elle n'est utilisée que pour ça et donc peut avoir une durée de vie longue, ces clés sont chiffrées et stockées en lieu sûr
La CA intermediate a une durée de vie de 10 ans car c'est lui qui va être utiliser en prod, pour evité de le renouveller trop souvent on lui donne une durée de vie de 10 ans, si cette durée est trop courte on devrait sortire les credentials de la CA root tout les X temps (dès que le CA intermediate arrive à expiration) ce qui serait compliqué d'un point de vu logistique, on lui donne donc une grande durée de vie mais plus court que la CA root
Les certificats clients ont une durée de vie de 90 jours car ils sont signé par la CA intermediate et peuvent donc être renouveller plus souvant sans grande logistique, de plus avoir un temps de validité plus courte minimise la perte de ce certificat, il est toujours révocable mais si un pirate le vol sans qu'on ne s'en rendent compte, il aura des accès durant "seulement" 90 jours. L'idéale serait de réduire la durée de vie des certificats clients.

La passphrase de la clé privée devrait être chiffré sur une clé USB, la passphrase de cette clé devrait être découpée et données par fragment à des personnes de confiance, de cette manière si une personne quitte l'entreprise elle n'a qu'un morceaux de la clé et ne peut pas la reconstituer.

## 2. Chain

Root, intermediate, leaves, with the extensions that constrain each one (pathlen, nameConstraints, EKU, SAN).

| Certificate | Subject, issuer | Constraining extensions | What they prevent |
|---|---|---|---|
| root CA | `C=FR, O=EPITA Lab, CN=EPITA Lab Root CA`, self-signed | `basicConstraints: critical, CA:TRUE, pathlen:1`; `keyUsage: critical, keyCertSign, cRLSign` | `pathlen:1`: below the root, one CA level only; a CA signed by the intermediate is refused. `keyUsage`: the root key signs certificates and CRLs, nothing else |
| intermediate CA | `C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`, signé par root CA | `Basic Constraints: critical, CA:TRUE, pathlen:0`; `Key Usage: critical, Digital Signature, Certificate Sign, CRL Sign` | `pathlen:0` : pas de possibilité de créer d'autres certificatats signant eux mêmes des certificats après. `keyUsage`: le certificat intermédiaire peut signé des certificats et les CRLs |
| feuille (www.lab.internal) | `C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`, signé par Lab Issuing CA | `BasicConstraints: critical, CA:FALSE`, `Key Usage: critical, Digital Signature`, `Extended Key Usage: TLS Web Server Authentication`| `CA:FALSE` : Ne peut pas signé d'autres certificats |
| feuille (alice) | `C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`, signé par Lab Issuing CA | `BasicConstraints: critical, CA:FALSE`, `Key Usage: critical, Digital Signature`, `Extended Key Usage: TLS Web Client Authentication`| `CA:FALSE` : Ne peut pas signé d'autres certificats |
| feuille (bob) | `C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`, signé par Lab Issuing CA | `BasicConstraints: critical, CA:FALSE`, `Key Usage: critical, Digital Signature`, `Extended Key Usage: TLS Web Client Authentication`| `CA:FALSE` : Ne peut pas signé d'autres certificats |
| feuille (URI:spiffe://lab.internal/billing) | `C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`, signé par Lab Issuing CA | `BasicConstraints: critical, CA:FALSE`, `Key Usage: critical, Digital Signature`, `Extended Key Usage: TLS Web Server Authentication`| `CA:FALSE` : Ne peut pas signé d'autres certificats |

Read them from the certificates, not from the config:
`openssl x509 -in root/certs/ca.cert.pem -noout -subject -issuer -ext basicConstraints,keyUsage`.

## 3. Key compromise

For the server key, a client key, the intermediate key and the root key: how would you notice,
what stops working or becomes unsafe, how do you recover, how long does it take?

### Server key (`identities/www/www.key.pem`)

- How you notice: nothing in this build detects it: no monitoring, no alert. You learn it from outside: the key
  found in a backup, a leak, an intrusion on the host.
- What becomes unsafe: whoever can redirect traffic (DNS, same network) can pose as `www.lab.internal`: clients send
  it their requests and trust its answers. It still cannot reach the API as alice: it has no client key. Past
  sessions stay unreadable: TLS 1.3 key exchange is ephemeral (forward secrecy). Nothing stops working.
- Recovery: new key and CSR in `client`, sign in `issuing-ca`, copy to `identities/www/`, restart nginx. Revoke the
  old serial and publish the CRL, but the clients do not check the server's revocation (`curl` reads no CRL by
  default): the old certificate stays accepted.
- How long: 10 minutes to reissue; the stolen certificate stays usable until it expires, at most 90 days.

### Client key

- How you notice:
- What becomes unsafe:
- Recovery:
- How long:

### Intermediate key

- How you notice:
- What becomes unsafe:
- Recovery:
- How long:

### Root key

- How you notice:
- What becomes unsafe:
- Recovery:
- How long:

## 4. Operational gaps

search answer to those questions/weaknesses

- the root key's passphrase: where is it, who knows it? What if that person leaves the company?
- the CRL expires after 7 days: what happens on day 8, and who regenerates it?
- the lab root is in no trust store: how would every laptop, server and container get it?
- the intermediate's key is not encrypted, unlike the root's. Search how it would be possible to use KMS for intermediate issuing CA.

