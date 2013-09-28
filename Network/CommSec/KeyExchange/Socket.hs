{-# LANGUAGE RecordWildCards #-}
module Network.CommSec.KeyExchange.Socket
    ( Network.CommSec.KeyExchange.Socket.connect
    , Network.CommSec.KeyExchange.Socket.accept
    , Net.listen, Net.bind, Net.socket
    , CS.send
    , CS.recv
    , CS.Connection
    , CS.close
    ) where

import Control.Concurrent.MVar
import Crypto.Types.PubKey.RSA
import Data.Traversable (traverse)
import Network.CommSec
import Network.CommSec.KeyExchange.Internal as I
import qualified Network.CommSec as CS
import qualified Network.CommSec.Package as CSP
import qualified Network.Socket as Net

connect :: Net.Socket
        -> Net.SockAddr
        -> [PublicKey]
        -> PrivateKey
        -> IO (Maybe (PublicKey, Connection))
connect socket addr pubKeys privateMe = do
    Net.connect socket addr
    Net.setSocketOption socket Net.NoDelay 1
    res <- I.keyExchangeInit socket pubKeys privateMe
    traverse (wrapContexts socket addr) res

accept  :: Net.Socket
        -> [PublicKey]
        -> PrivateKey
        -> IO (Maybe (PublicKey, Connection))
accept sock pubKeys privateMe = do
    (socket,sa) <- Net.accept sock
    Net.setSocketOption socket Net.NoDelay 1
    res <- keyExchangeResp socket pubKeys privateMe
    traverse (wrapContexts socket sa) res

-- Helper function for wrapping up the results of a key exchange into a 'Connection'
wrapContexts :: Net.Socket -> Net.SockAddr -> (PublicKey, CSP.OutContext, CSP.InContext) -> IO (PublicKey, Connection)
wrapContexts socket socketAddr (t, oCtx, iCtx) = do
  outCtx <- newMVar oCtx
  inCtx  <- newMVar iCtx
  return (t, Conn {..})
