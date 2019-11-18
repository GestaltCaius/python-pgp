# Inspiration

* PGP
* Signal
* DarkWire

```py

# Sender A
Sender.keys = RSA.generate_keys()

# Receiver B
Receiver.keys = RSA.generate_keys()

# Signature du message
M = 'Plain text message from A'
H = SHA512(M)
EH = RSA(H, Sender.keys.private)

# ZIP du message
message = [M, H]
zipped_message = [zip(m) for m in message]

# Chiffrement du message
secret_key = generate_key()
encrypted_message = [AES(m, secret_key) for m in zipped_message]

# Chiffrement de la secret key
encrypted_secret_key = RSA(secret_key, Receiver.keys.public)

encrypted_message.append(encrypted_secret_key)

# Envoi du message de A vers B

# On recupere la secret key
encrypted_secret_key = encryted_message[2]
secret_key = unRSA(encrypted_secret_key, Receiver.keys.private)

# On dechiffre M et EH compressed
zipped_message = [unAES(m, secret_key) for m in encrypted_message[0:1]]

# On dezippe
message = [unZIP(m) for m in zipped_message]

# On verifie le l'integrite et l'authentification du message
H = unRSA(message[1], Sender.keys.public)
received_message_hash = SHA512(message[0])
if H != received_message_hash:
    rise exception

print(message[0])

```

> Pourquoi utiliser une secret key et pas directement la cle publique du receiver ? Ca permet de faire du symetrique pour gagner en rapidite

# Axes d'ameliorations

## Utiliser LibSodium a la place de cryptography ?

Je n'ai pas la certitude que la lib cryptography soit si sûre.
La documentation officielle affiche ce message :

> DANGER
This is a “Hazardous Materials” module. You should ONLY use it if you’re 100% absolutely sure that you know what you’re doing because this module is full of land mines, dragons, and dinosaurs with laser guns.

[Source ici](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)

D'apres ce [thread reddit](https://www.reddit.com/r/Python/comments/5gn3q8/what_crypto_library_should_one_use_in_python/) il vaut mieux utiliser libsodium (PyNaCl).

Cependant on a utilise cryptography en cours donc je prefere utiliser cette lib pour me focaliser sur la comprehension des protocoles et non pas les implementations des algos.

