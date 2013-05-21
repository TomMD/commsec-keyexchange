{-# LANGUAGE RecordWildCards, BangPatterns, OverloadedStrings #-}
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
    , CS.send, CS.recv, CS.Connection, CS.close
    , Net.HostName, Net.PortNumber
    ) where

import qualified Network.Socket as Net
import qualified Network.Socket.ByteString as NetBS
import Crypto.Types.PubKey.RSA
import Crypto.Cipher.AES128
import Crypto.Classes
import Crypto.Util
import Crypto.Modes (zeroIV)
import Crypto.Hash.CryptoAPI
import Control.Exception (bracket)
import Control.Monad
import Control.Monad.CryptoRandom
import Data.Maybe (isNothing, fromMaybe)
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

import qualified Network.CommSec.KeyExchange.Internal as I
import qualified Network.CommSec.KeyExchange.Socket as S

-- |Connect to the specified host and port, establishing a secure,
-- authenticated connection with a party holding the public key.
connect :: Net.HostName
        -> Net.PortNumber
        -> [PublicKey]
        -> PrivateKey
        -> IO (PublicKey,Connection)
connect host port thems us = do
    ai       <- resolve1 (Just host) port
    socket   <- openSocket ai
    res      <- S.connect socket (Net.addrAddress ai) thems us
    case res of
      Nothing -> fail "Could not agree on a key."
      Just x  -> return x

-- | Return the first 'AddrInfo' suitable for establishing a
-- stream connection to the given host on the given port.
resolve1 :: Maybe Net.HostName -> Net.PortNumber -> IO Net.AddrInfo
resolve1 h port = do
  let passiveFlag
         | isNothing h = [Net.AI_PASSIVE]
         | otherwise = []
      flags = Net.defaultHints
                { Net.addrSocketType = Net.Stream
                , Net.addrFamily     = Net.AF_INET -- XXX unnecessarily restrictive
                , Net.addrFlags      = passiveFlag ++ [Net.AI_ADDRCONFIG]
                }
  ais <- Net.getAddrInfo (Just flags) h (Just (show port))
  case ais of
    []   -> fail ("Could not resolve host " ++ fromMaybe "" h)
    ai:_ -> return ai

-- | Open a new socket given the parameters in an 'AddrInfo'
openSocket :: Net.AddrInfo -> IO Net.Socket
openSocket Net.AddrInfo{..} = Net.socket addrFamily addrSocketType addrProtocol

-- |Listen for and accept a connection on the host and port, establishing
-- a secure, authenticated connection with a party holding the specified
-- public key.
accept :: Net.PortNumber -> [PublicKey] -> PrivateKey -> IO (PublicKey,Connection)
accept port thems us = do
    ai <- resolve1 Nothing port
    bracket (openSocket ai) Net.close $ \sock -> do
      Net.setSocketOption sock Net.ReuseAddr 1
      Net.bind sock (Net.addrAddress ai)
      Net.listen sock 1
      mconn <- S.accept sock thems us
      case mconn of
          Nothing -> fail "Failed to perform key exchange"
          Just res -> return res
