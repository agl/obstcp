module Main where

import Graphics.Rendering.Cairo as C
import Text.Printf (printf)

-- These are the standard Youtube values
videoWidth = 320 :: Int
videoHeight = 240 :: Int
framesPerSecond = 30 :: Float

pushTransMatrix :: C.Render a -> C.Render a
pushTransMatrix f = do
  m <- C.getMatrix
  r <- f
  C.setMatrix m
  return r

centerText :: String -> C.Render ()
centerText tx = do
  pushTransMatrix $ do
    ex <- C.textExtents tx
    translate (0-(textExtentsWidth ex / 2)) 0
    showText tx
    fill

setup :: C.Render ()
setup = do
  translate 160 120
  scale 240 240

blackBackground :: C.Render ()
blackBackground = do
  setSourceRGBA 0 0 0 1
  rectangle (-0.66) (-0.66) 1.33 1.33
  fill

centerWord :: String -> C.Render ()
centerWord tx = do
  blackBackground
  selectFontFace "monospace" FontSlantNormal FontWeightNormal
  setFontSize 0.1
  setSourceRGBA 0.2 0.6 0 1
  centerText tx
  fill

data SceneElement = SStatic (C.Render ())
                  | SDyn Float (Float -> C.Render ())
type Scene = [(Float, SceneElement)]

sceneDraw :: Scene -> Float -> C.Render ()
sceneDraw scene time = do
  let activeElements = [x | x@(start, elem) <- scene, time >= start]
      r (start, SStatic f) = f
      r (start, SDyn duration f) = f fraction where fraction = min 1.0 ((time - start) / duration)
  setup
  mapM_ r activeElements

type Video = [(Float, Scene)]

single :: C.Render () -> Scene
single f = [(0, SStatic f)]

video :: Video
video = [ (0, single $ centerWord "test1")
        , (1, single $ centerWord "test2")
        , (2, single $ centerWord "test3")
        ]

vidrn :: Video -> Float -> IO ()
vidrn vid duration = doFrames 0 (0 :: Int) where
  frameStep = 1 / framesPerSecond
  doFrames currentTime frameno
    | currentTime > duration = return ()
    | otherwise = do
        let (start, scene) = head $ reverse $ [x | x@(start, scene) <- vid, currentTime >= start]
            expired = currentTime - start
        printf " : %f %d %f\n" currentTime frameno expired
        surface <- C.createImageSurface C.FormatARGB32 videoWidth videoHeight
        renderWith surface $ sceneDraw scene expired
        surfaceWriteToPNG surface $ printf "out%05d.png" frameno
        surfaceFinish surface
        doFrames (currentTime + frameStep) (frameno + 1)

main = do
  vidrn video 3
