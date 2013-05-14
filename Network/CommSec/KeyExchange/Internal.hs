{-# LANGUAGE RecordWildCards, BangPatterns, OverloadedStrings #-}
-- |This module provides an authenticated key exchange using the station to
-- station protocol and RSA signatures for authentication.
--
module Network.CommSec.KeyExchange.Internal
    ( keyExchangeInit, keyExchangeResp
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
    g <- newGenIO :: IO CtrDRBG
    let (x,_) = throwLeft $ crandomR (1,thePrime-2) g
        ax    = modexp theGenerator x thePrime
    return (x,ax)

buildSigMessage :: AESKey -> PrivateKey -> Integer -> Integer -> ByteString
buildSigMessage aesKey privateMe ax ay =
    let publicMe = encode . sha256 . encode . private_pub $ privateMe
        mySig    = signExps ax ay privateMe
        plaintext = B.append publicMe mySig
    in fst .  ctr aesKey zeroIV $ plaintext

parseSigMessage :: AESKey -> [PublicKey] -> ByteString -> Integer -> Integer -> Maybe PublicKey
parseSigMessage aesKey thems enc ax ay =
    let (pubHash, theirSig) = B.splitAt (256 `div` 8)
                            . fst . unCtr aesKey zeroIV
                            $ enc
        pubHashes = map (\k -> (encode (sha256 $ encode k),k)) thems
    in case lookup pubHash pubHashes of
            Just publicThem ->
                if (not $ verifyExps ax ay theirSig publicThem)
                    then Nothing
                    else Just publicThem
            Nothing -> Nothing

-- |@keyExchangeResp sock pubKeys me@
--
-- Act as the responder in an authenticated key exchange using the socket
-- @sock@ as the communications channel, the public keys @pubKeys@ to
-- verify the end point and the private key @me@ to prove ourself.
--
-- If the initiator uses one of the assocated public keys for
-- authentication, it will return the tuple of the public key used
-- and the contexts created.  If the initiator does not use on of
-- these keys then @Nothing@ is returned.
keyExchangeResp :: Net.Socket
                -> [PublicKey]
                -> PrivateKey
                -> IO (Maybe (PublicKey , OutContext, InContext))
keyExchangeResp sock thems privateMe = do
    ax     <- (either error id . decode) `fmap` recvMsg sock
    (y,ay) <- getXaX
    let axy = modexp ax y thePrime
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
        msg2     = buildSigMessage aesKey1 privateMe ay ax
        outCtx   = Out 2 salt1 aesKey1
        inCtx    = InStrict 1 salt2 aesKey2
    sendMsg sock (runPut $ put ay >> put msg2)
    encSaAxAy <- recvMsg sock
    case parseSigMessage aesKey2 thems encSaAxAy ax ay of
        Just t  -> return (Just (t, outCtx, inCtx))
        Nothing -> return Nothing

-- |@keyExchangeInit sock pubKeys me@
--
-- Act as the initiator in an authenticated key exchange using the socket
-- @sock@ as the communications channel, the public keys @pubKeys@ to
-- verify the end point and the private key @me@ to prove ourself.
--
-- If the responder uses one of the assocated public keys for
-- authentication, it will return the tuple of the public key used
-- and the contexts created.  If the responder does not use ond of
-- these keys then @Nothing@ is returned.
--
-- The current design assumes the responder accepts our signature -
-- the responder can reject our signature silently.
keyExchangeInit :: Net.Socket
                -> [PublicKey]
                -> PrivateKey
                -> IO (Maybe (PublicKey, OutContext, InContext))
keyExchangeInit sock thems privateMe = do
    -- our secret big number, x, and a^x for exchange.
    (x,ax) <- getXaX
    sendMsg sock (encode ax)
    msg2 <- recvMsg sock
    let (ay, encSbAyAx) = either error id (decodePkg msg2)
        decodePkg = runGet (do i <- get -- Integer
                               e <- get -- Encrypted signature
                               return (i,e))
        axy = modexp ay x thePrime :: Integer
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
        msg3     = buildSigMessage aesKey2 privateMe ax ay
        outCtx   = Out 2 salt2 aesKey2
        inCtx    = InStrict 1 salt1 aesKey1
    case parseSigMessage aesKey1 thems encSbAyAx ay ax of
        Just t -> do
            sendMsg sock msg3
            return (Just (t,outCtx,inCtx))
        Nothing -> do
            sendMsg sock "FAIL"
            return Nothing

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

instance Serialize PublicKey where
    put (PublicKey {..}) = put public_size >> put public_n >> put public_e
    get = do
        public_size <- get
        public_n <- get
        public_e <- get
        return (PublicKey {..})
