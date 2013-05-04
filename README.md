##CommSec Key Exchange
CommSec key exchange builds on the [commsec](https://github.com/TomMD/commsec)
package to provide a simple key agreement for secure communications.  To
communicate, the users need to have preshared RSA public keys.

Short of parsing SSH keys, see below, you can use this package in combination with the
[RSA](http://hackage.haskell.org/package/RSA) package.  Just use `generateKeyPair`
on each system.  Exchange public keys out of band, and connect using the `accept` and
`connect` primitives from `Network.CommSec.KeyExchange`.

##Secure Communications using SSH Keys
Once a pull request is accepted, using crypto-pubkey-openssh should be the easiest
method. From the shell, just generate RSA keys:

    $ ssh-keygen
    ...enter a path...

Then exchange the public keys (`id_rsa.pub`).

Now your programs will be able to read in these keys and perform key agreement:

    {-# LANGUAGE OverloadedStrings #-}
    import Crypto.PubKey.OpenSsh
    import qualified Data.ByteString as B
    import qualified Data.ByteString.Char8 as BC
    import Network.CommSec.KeyExchange

    main = do
        -- Step 1: (not shown) get file paths, host, and port somehow.
        -- Step 2: Read in the keys
        OpenSshPrivateKeyRsa priv  <- (either error id . (\x -> decodePrivate x Nothing)) `fmap`
                                      B.readFile myPrivateKeyFile
        OpenSshPublicKeyRsa them _ <- (either error id . decodePublic) `fmap`
                                      B.readFile theirPublicKeyFile

        -- Step 3: Listen for and accept a connection (alternatively: connect to a listener).
        conn <- if listener
                 then accept  host port [them] priv
                 else connect host port [them] priv

        -- Step 4: Communicate
        send conn "hello!"
        recv conn >>= BC.print

##Note
This key agreement protocol is based on the station to station protocol.  There
is minimal testing and no peer review.  As with the commsec package, this is
only intended to be 'morally correct' for purposes of prototyping (it should
have computation costs similar to a truely secure system), no assurances are
given as to its actual security.
