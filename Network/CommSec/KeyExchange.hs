{-# LANGUAGE RecordWildCards, BangPatterns #-}
-- |This module provides an authenticated key exchange using the station to
-- station protocol and RSA signatures for authentication.
--
-- For example, after presharing ssh keys generated using ssh-keygen:
--
-- @
--  import Crypto.PubKey.OpenSsh
--  import qualified Data.ByteString as B
--  import Network.CommSec.KeyExchange
--
--  main = do
--      -- Step 1: (not shown) get file paths, host, and port somehow.
--      -- Step 2: Read in the keys
--      OpenSshPrivateKeyRsa priv <- (either error id . (\x -> decodePrivate x)) `fmap` B.readFile myPrivateKeyFile
--      OpenSshPublicKeyRsa them _ <- (either error id . decodePublic) `fmap` B.readFile theirPublicKeyFile
--
--      -- Step 3: Listen for and accept a connection (or connect to the listener)
--      if listener
--          then accept host port them priv
--          else connect host port them priv
-- @
module Network.CommSec.KeyExchange
    ( connect
    , accept
    , keyExchangeInit, keyExchangeResp
    , CS.send, CS.recv, CS.Connection, Net.HostName, Net.PortNumber
    ) where

import qualified Network.Socket as Net
import qualified Network.Socket.ByteString as NetBS
import Crypto.Types.PubKey.RSA
import Crypto.Cipher.AES128
import Crypto.Classes
import Crypto.Util
import Crypto.Modes (zeroIV)
import Crypto.Hash.CryptoAPI
import Control.Monad
import Control.Monad.CryptoRandom
import qualified Codec.Crypto.RSA as RSA
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (fromStrict, toChunks)
import qualified Data.ByteString.Lazy as L
import Data.Serialize
import Data.Serialize.Get
import Data.Serialize.Put
import Crypto.Random.DRBG
import Data.Maybe (listToMaybe)
import Control.Concurrent
import Foreign.Storable

-- For types
import qualified Network.CommSec as CS
import Network.CommSec hiding (accept, connect)
import Network.CommSec.Package (InContext(..), OutContext(..))

-- |This prime is from RFC 5114 section 2.3
thePrime :: Integer
thePrime = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

-- A common generator, refered to as "a" in literature.
theGenerator :: Integer
theGenerator = 5

-- |Sign exponents:  Sign(q_y, Sha256(a | b))
signExps :: Integer -> Integer -> PrivateKey -> ByteString
signExps a b k = L.toStrict . RSA.sign k $ encodeExps a b

-- |Verify exponents and other party was signed as:  Sign(q_y, Sha256(a | b))
verifyExps :: Integer -> Integer -> ByteString -> PublicKey -> Bool
verifyExps a b sig k = RSA.verify k (encodeExps a b) (fromStrict sig)

-- |Serialize exponents in an agreed upon format
encodeExps :: Integer -> Integer -> L.ByteString
encodeExps a b = fromStrict . runPut $ put a >> put b

-- |Get the secret value @x@ and a publicly sharable value @theGenerator
-- ^ x@
getXaX :: IO (Integer, Integer)
getXaX = do
    g <- newGenIO :: IO HmacDRBG
    let (x,_) = throwLeft $ crandomR (1,thePrime-2) g
        ax    = modexp theGenerator x thePrime
    return (x,ax)

-- |@keyExchangeResp sock them me@
--
-- Act as the responder in an authenticated key exchange using the socket
-- @sock@ as the communications channel, the public key @them@ to verify
-- the end point and the private key @me@ to prove ourself.
keyExchangeResp :: Net.Socket -> PublicKey -> PrivateKey -> IO (OutContext, InContext)
keyExchangeResp sock publicThem privateMe = do
    (y,ay) <- getXaX
    ax     <- (either error id . decode) `fmap` recvMsg sock
    let axy = ax * ay `mod` thePrime
        sharedSecret = encode . sha256 $ i2bs (2048 `div` 8) axy
        shared512    = expandSecret sharedSecret (16 + 16 + 4 + 4)
        -- Split the 512 bit secret into [ Key 1 (128b) | Key 2 (128b) | salt 1 (32b) | salt 2 (32 b) ]
        (aesKey1, aesKey2, salt1, salt2) =
            let (key1tmp, rest1)  = B.splitAt (keyLengthBytes `for` aesKey1) shared512
                (key2tmp, rest2)  = B.splitAt (keyLengthBytes `for` aesKey2) rest1
                (salt1tmp, rest3) = B.splitAt (sizeOf salt1) rest2
                salt2tmp          = B.take    (sizeOf salt2) rest3
                op = fromIntegral . bs2i
                bk = maybe (error "failed to build key") id . buildKey
            in (bk key1tmp, bk key2tmp, op salt1tmp, op salt2tmp)
        mySig    = signExps ay ax privateMe
        (enc, _) = ctr aesKey1 zeroIV mySig
        outCtx = Out 2 salt1 aesKey1
        inCtx  = InStrict 1 salt2 aesKey2
    sendMsg sock (runPut (put ay >> put enc))
    encSaAxAy <- recvMsg sock
    let theirSig = fst $ unCtr aesKey2 zeroIV encSaAxAy
    when (not $ verifyExps ax ay theirSig publicThem)
           (error "RESP: Verification failed when exchanging key.  Man in the middle?")
    return (outCtx, inCtx)

-- |@keyExchangeInit sock them me@
--
-- Act as the initiator in an authenticated key exchange using the socket
-- @sock@ as the communications channel, the public key @them@ to verify
-- the end point and the private key @me@ to prove ourself.
keyExchangeInit :: Net.Socket -> PublicKey -> PrivateKey -> IO (OutContext, InContext)
keyExchangeInit sock publicThem privateMe = do
    -- our secret big number, x, and a^x for exchange.
    (x,ax) <- getXaX
    sendMsg sock (encode ax)
    pkg <- recvMsg sock
    let (ay, encSbAyAx) = either error id (decodePkg pkg)
        decodePkg = runGet (do i <- get -- Integer
                               e <- get -- Encrypted signature
                               return (i,e))
        axy = ax * ay `mod` thePrime :: Integer
        sharedSecret = encode . sha256 $ i2bs (2048 `div` 8) axy
        shared512    = expandSecret sharedSecret 64
        -- Split the 512 bit secret into [ Key 1 (128b) | Key 2 (128b) | salt 1 (32b) | salt 2 (32 b) ]
        (aesKey1, aesKey2, salt1, salt2) =
            let (key1tmp, rest1)  = B.splitAt (keyLengthBytes `for` aesKey1) shared512
                (key2tmp, rest2)  = B.splitAt (keyLengthBytes `for` aesKey2) rest1
                (salt1tmp, rest3) = B.splitAt (sizeOf salt1) rest2
                salt2tmp          = B.take    (sizeOf salt2) rest3
                op = fromIntegral . bs2i
                bk = maybe (error "failed to build key") id . buildKey
            in (bk key1tmp, bk key2tmp, op salt1tmp, op salt2tmp)
        mySig = signExps ax ay privateMe
        (enc, _) = ctr aesKey2 zeroIV mySig
        outCtx = Out 2 salt2 aesKey2
        inCtx  = InStrict 1 salt1 aesKey1
        theirSig = fst $ unCtr aesKey1 zeroIV encSbAyAx
    when (not $ verifyExps ay ax theirSig publicThem)
           (error "INIT: Verification failed when exchanging key.  Man in the middle?")
    sendMsg sock enc
    return (outCtx, inCtx)

connect :: Net.HostName -> Net.PortNumber -> PublicKey -> PrivateKey -> IO Connection
connect host port them us = do
    sockaddr <- resolve host port
    socket   <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.connect socket sockaddr
    Net.setSocketOption socket Net.NoDelay 1
    Net.setSocketOption socket Net.ReuseAddr 1
    (oCtx, iCtx) <- keyExchangeInit socket them us
    inCtx  <- newMVar iCtx
    outCtx <- newMVar oCtx
    return (Conn {..})
  where
      resolve :: Net.HostName -> Net.PortNumber -> IO Net.SockAddr
      resolve h port = do
        ai <- Net.getAddrInfo (Just $ Net.defaultHints {
                                    Net.addrFamily = Net.AF_INET, Net.addrSocketType = Net.Stream } ) (Just h) (Just (show port))
        return (maybe (error $ "Could not resolve host " ++ h) Net.addrAddress (listToMaybe ai))

accept :: Net.PortNumber -> PublicKey -> PrivateKey -> IO Connection
accept port them us = do
    let sockaddr = Net.SockAddrInet port Net.iNADDR_ANY
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.setSocketOption sock Net.ReuseAddr 1
    Net.bind sock sockaddr
    Net.listen sock 1
    socket <- fst `fmap` Net.accept sock
    Net.setSocketOption socket Net.NoDelay 1
    Net.close sock
    (oCtx, iCtx) <- keyExchangeResp socket them us
    outCtx <- newMVar oCtx
    inCtx  <- newMVar iCtx
    return (Conn {..})

recvMsg :: Net.Socket -> IO ByteString
recvMsg s = do
    lenBS <- recvAll s 4
    let len = fromIntegral . either error id . runGet getWord32be $ lenBS
    recvAll s len

recvAll :: Net.Socket -> Int -> IO ByteString
recvAll s nr = go nr []
  where
    go 0 x = return $ B.concat (reverse x)
    go n x = do
        bs <- NetBS.recv s n
        go (n - B.length bs) (bs:x)

sendMsg :: Net.Socket -> ByteString -> IO ()
sendMsg s msg = do
    let pkt = B.append (runPut . putWord32be . fromIntegral . B.length $ msg) msg
    NetBS.sendAll s pkt

keyLengthBytes = fmap ((`div` 8) . (+7)) keyLength

sha256 :: ByteString -> SHA256
sha256 bs = hash' bs

modexp :: Integer -> Integer -> Integer -> Integer
modexp b e n = go 1 b e
  where
    go !p _ 0 = p
    go !p !x !e =
        if even e
          then go p (mod (x*x) n) (div e 2)
          else go (mod (p*x) n) x (pred e)

