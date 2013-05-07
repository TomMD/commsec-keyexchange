{-# LANGUAGE RecordWildCards #-}
module Network.CommSec.KeyExchange.Socket
    ( Network.CommSec.KeyExchange.Socket.connect
    , Network.CommSec.KeyExchange.Socket.accept
    , Net.listen, Net.socket
    , CS.send
    , CS.recv
    , CS.Connection
    , CS.close
    ) where

import Network.CommSec
import qualified Network.Socket as Net
import Control.Concurrent.MVar
import Crypto.Types.PubKey.RSA
import Network.CommSec.KeyExchange.Internal as I
import qualified Network.CommSec as CS

connect :: Net.Socket
        -> Net.SockAddr
        -> [PublicKey]
        -> PrivateKey
        -> IO (Maybe (PublicKey, Connection))
connect socket addr pubKeys privateMe = do
    Net.connect socket addr
    Net.setSocketOption socket Net.NoDelay 1
    res <- I.keyExchangeInit socket pubKeys privateMe
    case res of
      Nothing -> return Nothing
      Just (t,oCtx,iCtx) -> do
          inCtx  <- newMVar iCtx
          outCtx <- newMVar oCtx
          return (Just (t,Conn{..}))

accept  :: Net.Socket
        -> [PublicKey]
        -> PrivateKey
        -> IO (Maybe (PublicKey, Connection))
accept sock pubKeys privateMe = do
    (socket,_) <- Net.accept sock
    Net.setSocketOption socket Net.NoDelay 1
    res <- keyExchangeResp socket pubKeys privateMe
    case res of
      Nothing -> return Nothing
      Just (t, oCtx, iCtx) -> do
          outCtx <- newMVar oCtx
          inCtx  <- newMVar iCtx
          return (Just (t, Conn {..}))
