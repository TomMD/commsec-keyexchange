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
    sockaddr <- resolve host port
    socket   <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    maybe (error "Could not agree on a key.") id
          `fmap` (S.connect socket sockaddr thems us)
  where
      resolve :: Net.HostName -> Net.PortNumber -> IO Net.SockAddr
      resolve h port = do
        ai <- Net.getAddrInfo (Just $ Net.defaultHints {
                                    Net.addrFamily = Net.AF_INET, Net.addrSocketType = Net.Stream } ) (Just h) (Just (show port))
        return (maybe (error $ "Could not resolve host " ++ h) Net.addrAddress (listToMaybe ai))

-- |Listen for and accept a connection on the host and port, establishing
-- a secure, authenticated connection with a party holding the specified
-- public key.
accept :: Net.PortNumber -> [PublicKey] -> PrivateKey -> IO (PublicKey,Connection)
accept port thems us = do
    let sockaddr = Net.SockAddrInet port Net.iNADDR_ANY
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.setSocketOption sock Net.ReuseAddr 1
    Net.bind sock sockaddr
    Net.listen sock 1
    -- socket <- fst `fmap` Net.accept sock
    mconn  <- S.accept sock thems us
    case mconn of
        Nothing -> error "Failed to perform key exchange"
        Just (t,c) -> do
            Net.close sock
            return (t,c)
