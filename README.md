ncGKS
=====

A PGP Keyserver written in Bash shell script. "Netcat GnuPG Key Server", or commonly known as "Bash GKS"

### Why write this?
The PGP Key server scene (admittedly, a small scene) is alarmingly homogenous with the dominant [SKS](http://sks-keyservers.net/) running everywhere.

It's good to have other options too! In this case, we are different/advantageous on the following points:
* **Low System Requirements** - Runs on minimal hardware/OS setups (i.e. wireless SD cards, routers) without the need to install Ocaml and Berkeley DB (in the case of SKS).
* **Dependencies:** None, really. Perl and awk free! [GnuPG, netcat, bash, tr, grep, GNU Coreutils: mkfifo, rm, sed, echo, printf]
* **Fast Adhoc Deployments** - This is perfect for setting up something small for an offline group of people to share, manage, and easily exchange keys.

### What it is not?
I pity the fool who runs this as a public facing service.

* **Insecure** - Runs gpg directly on raw input with minor sanitization.
* **No database, no caching** - Backed by GPG's flat file keystore, which certainly has not won any distinctions in industry.
* **Netcat** - To ensure wide compatibility, netcat is used such that it can only handle one connection at a time.
* **Service Easily DOS'd** - Following the previous point, the service can be easily locked up with requests even with connection timeouts.
* **No replication** - For all the reasons above, it doesn't have fancy reconciliation and replication of data to other instances of the keyserver.

### How do I use it?
```bash
bash ncGKS.sh
```
The keyserver listens on port 11371 for incoming requests. Pull up [http://localhost:11371/](http://localhost:11371/) to take a look.

Point your GnuPG client to this keyserver. In ~/.gnupg/config, simply add "keyserver hkp://this-server-address"


#### How do I search for a key from the keyserver from GnuPG?
```
gpg --search-key <keywords>
```

#### How do I send a key to the keyserver from GnuPG?
```
gpg --send-key <951EE9FB>
```

#### How do I retrieve a key from the keyserver from GnuPG?
```
gpg --recv-key <951EE9FB>
```

### Testing?

* Works with GNU bash, version 4.2.42(2)-release (i386-apple-darwin12.2.1), netcat version unknown, and gpg (GnuPG/MacGPG2) 2.0.19
