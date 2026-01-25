{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Weigh

main :: IO ()
main = mainWith (pure ())
