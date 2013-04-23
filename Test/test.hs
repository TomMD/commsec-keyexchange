{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.CommSec.KeyExchange
-- import Network.CommSec
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import Crypto.PubKey.OpenSsh
import Control.Concurrent
import System.FilePath


port :: PortNumber
port = 1874
host = "127.0.0.1"

readSSHKeys :: FilePath -> IO (OpenSshPublicKey, OpenSshPrivateKey)
readSSHKeys fp = do
    pub  <- (either error id . decodePublic) `fmap` B.readFile (fp <.> "pub")
    priv <- (either error id . (\x -> decodePrivate x Nothing)) `fmap` B.readFile fp
    return (pub,priv)

main = do
    (pubA,privA) <- readSSHKeys "id_rsa"
    (pubB,privB) <- readSSHKeys "id_rsa2"
    {-print pubB
    print pubA
    print privB
    print privA
    -}
    forkIO $ listener privA pubB
    threadDelay 1000000
    connecter privB pubA

listener priv pub = do
    conn <- accept port pub priv
    recv conn >>= print
    send conn "Hello to you too!"
    return ()

connecter priv pub = do
    conn <- connect host port pub priv
    send conn "Hello!"
    recv conn >>= print
    return ()
