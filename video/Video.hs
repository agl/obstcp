module Main where

import           Graphics.Rendering.Cairo as C
import           Text.Printf (printf)

-- These are the standard Youtube values
videoWidth = 320 :: Int
videoHeight = 240 :: Int
framesPerSecond = 30 :: Double

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
    C.showText tx
    fill

setup :: C.Render ()
setup = do
  translate 160 120
  scale 240 240

background :: Double -> C.Render ()
background n = do
  setSourceRGBA n n n 1
  rectangle (-0.67) (-0.67) 1.34 1.34
  fill

endText = do
  setSourceRGBA 0 0 0 1

  selectFontFace "serif" FontSlantNormal FontWeightNormal
  setFontSize 0.1
  pushTransMatrix $ do
    ex <- C.textExtents "Obfuscated"
    translate (0-(textExtentsWidth ex / 2)) (-0.25)
    C.showText "Obfuscated"
    fill
  setFontSize 0.15
  pushTransMatrix $ do
    ex <- C.textExtents "TCP"
    translate (0-(textExtentsWidth ex / 2)) (-0.1)
    C.showText "TCP"
    fill
  setFontSize 0.075

  pushTransMatrix $ do
    ex <- C.textExtents "code.google.com/p/obstcp"
    translate (0-(textExtentsWidth ex / 2)) (0)
    C.showText "code.google.com/p/obstcp"
    fill

  pushTransMatrix $ do
    ex <- C.textExtents "Music by Triad (CC-by-sa)"
    translate (0-(textExtentsWidth ex / 2)) (0.2)
    C.showText "Music by Triad (CC-by-sa)"
    fill


blackBackground = background 0

centerWord :: String -> C.Render ()
centerWord tx = do
  blackBackground
  selectFontFace "monospace" FontSlantNormal FontWeightNormal
  setFontSize 0.1
  setSourceRGBA 0.2 0.6 0 1
  centerText tx
  fill

textAt :: String -> Double -> Double -> C.Render ()
textAt tx x y = do
  pushTransMatrix $ do
    selectFontFace "monospace" FontSlantNormal FontWeightNormal
    setFontSize 0.1
    setSourceRGBA 0.2 0.6 0 1
    translate x y
    ex <- C.textExtents tx
    translate (0-(textExtentsWidth ex / 2)) 0
    showText tx
    fill

textMove :: String -> Double -> Double -> Double -> Double -> Double -> Double -> Double -> C.Render ()
textMove tx x1 y1 x2 y2 delay sustain time
  | time <= delay = textAt tx x1 y2
  | time >= (delay + sustain) = textAt tx x2 y2
  | otherwise = do
      let fraction = (time - delay) / sustain
          x = x1 + ((x2 - x1) * fraction)
          y = y1 + ((y2 - y1) * fraction)
      textAt tx x y

backgroundFade :: Double -> Double -> Double -> Double -> C.Render ()
backgroundFade start end sustain time
  | time >= sustain = background end
  | otherwise = background (start + delta * fraction) where
      delta = end - start
      fraction = time / sustain

data TypeBox = Roman String
             | Italic String
             | Superscript String
             deriving (Show)

typeset :: [TypeBox] -> C.Render ()
typeset boxes = do
  let setupRoman = do
        selectFontFace "monospace" FontSlantNormal FontWeightNormal
        setFontSize 0.1
      setupItalic = do
        selectFontFace "monospace" FontSlantItalic FontWeightNormal
        setFontSize 0.1
      setupSuperscript = do
        selectFontFace "monospace" FontSlantItalic FontWeightNormal
        setFontSize 0.05

  let boxWidth (Roman s) = setupRoman >> C.textExtents s >>= return . textExtentsXadvance
      boxWidth (Italic s) = setupItalic >> C.textExtents s >>= return . textExtentsXadvance
      boxWidth (Superscript s) = setupSuperscript >> C.textExtents s >>= return . textExtentsXadvance

  let boxDraw :: TypeBox -> C.Render ()
      boxDraw (Roman s) = setupRoman >> C.showText s >> C.fill
      boxDraw (Italic s) = setupItalic >> C.showText s >> C.fill
      boxDraw (Superscript s) = do
        pushTransMatrix $ do
          setupSuperscript
          translate 0 (-0.05)
          C.showText s
          C.fill

  blackBackground
  setSourceRGBA 0.2 0.6 0 1
  widths <- mapM boxWidth boxes
  pushTransMatrix $ do
    translate (0-(sum widths / 2)) 0
    mapM_ (\(box, width) -> boxDraw box >> translate width 0) $ zip boxes widths

data SceneElement = SStatic (C.Render ())
                  | SDyn (Double -> C.Render ())
type Scene = [(Double, SceneElement)]

dhSceneStart = 72.7
dhScene = [ (72.7 - dhSceneStart, SStatic blackBackground)
          , (72.7 - dhSceneStart, SStatic $ textAt "Alice" (-0.5) (-0.35))
          , (74.2 - dhSceneStart, SStatic $ textAt "Bob" 0.5 (-0.35))
          , (77 - dhSceneStart, SStatic $ textAt "a" (-0.45) (-0.1))
          , (80 - dhSceneStart, SStatic $ textAt "b" (0.45) (-0.1))
          , (82.7 - dhSceneStart, SDyn $ textMove "9a" (-0.45) 0 0.45 0 0.7 1.5)
          , (82.7 - dhSceneStart, SDyn $ textMove "9b" 0.45 0 (-0.45) 0 0.7 1.5)
          , (87.5 - dhSceneStart, SStatic $ textAt "9ab" (-0.45) 0.1)
          , (87.5 - dhSceneStart, SStatic $ textAt "9ab" 0.45 0.1)
          , (91.2 - dhSceneStart, SStatic $ textAt "81ab" 0 0)
          ]

tcpSceneStart = 243.3
tcpScene = [ (243.3 - tcpSceneStart, SStatic blackBackground)
           , (243.3 - tcpSceneStart, SStatic $ textAt "Client" (-0.48) (-0.35))
           , (244.5 - tcpSceneStart, SStatic $ textAt "Server" 0.48 (-0.35))
           , (246.6 - tcpSceneStart, SDyn $ textMove "SYN" (-0.45) (-0.1) (0.45) (-0.1) 0 1)
           , (250.3 - tcpSceneStart, SDyn $ textMove "SYNACK" (0.45) 0 (-0.45) 0 0 1)
           , (252.2 - tcpSceneStart, SDyn $ textMove "ACK" (-0.45) (0.1) (0.45) (0.1) 0 1)
           ]

endScene = [ (0, SDyn $ backgroundFade 0 1 4)
           , (0, SStatic $ endText )
           ]

startFade = [ (0, SDyn $ backgroundFade 1 0 4) ]

sceneDraw :: Scene -> Double -> C.Render ()
sceneDraw scene time = do
  let activeElements = [x | x@(start, elem) <- scene, time >= start]
      r (start, SStatic f) = f
      r (start, SDyn f) = f (time - start)
  setup
  mapM_ r activeElements

type Video = [(Double, Scene)]

single :: C.Render () -> Scene
single f = [(0, SStatic f)]

video :: Video
video = [ (0, startFade)
        , (5.3, single $ centerWord "NebuAd")
        , (6.3, single $ centerWord "Phorm")
        , (7.3, single $ centerWord "Warrantless")
        , (7.8, single $ centerWord "Wiretapping")
        , (10, single $ blackBackground)
        , (18.9, single $ centerWord "Salsa20/8")
        , (20.25, single $ centerWord "Poly1305")
        , (21.7, single $ centerWord "Curve25519")
        , (24, single $ blackBackground)
        , (33, single $ centerWord "<section>")
        , (34, single $ blackBackground)
        , (35.8, single $ centerWord "SSL/TLS")
        , (47.8, single $ blackBackground)
        , (44.25, single $ centerWord "www.google.com")
        , (45, single $ blackBackground)
        , (52.9, single $ centerWord "1.")
        , (54, single $ centerWord "Aggregate security")
        , (57, single $ blackBackground)
        , (66.9, single $ centerWord "(i.e. public WiFi)")
        , (68.9, single $ blackBackground)
        , (72.7, sceneTimeMangle dhScene)
        , (104.9, single $ blackBackground)
        , (117.45, single $ typeset [Italic "x", Roman " = ", Italic "g", Superscript "y", Roman " (mod ", Italic "p", Roman ")"])
        , (117.45, single $ typeset [Italic "x", Roman " = ", Italic "g", Superscript "y", Roman " (mod ", Italic "p", Roman ")"])
        , (121.75, single $ typeset [Italic "y", Superscript "2", Roman " = ", Italic "x", Superscript "3", Roman " + 486662", Italic "x", Superscript "2", Roman " + ", Italic "x"])
        , (124.5, single $ blackBackground)
        , (128.6, single $ centerWord "<section>")
        , (129.6, single $ blackBackground)
        , (145.45, single $ centerWord "2.")
        , (146.7, single $ centerWord "0 extra RTT")
        , (148.5, single $ blackBackground)
        , (149.0, single $ centerWord "<section>")
        , (150.0, single $ blackBackground)
        , (169.8, single $ centerWord "3.")
        , (170.9, single $ centerWord "Transparency")
        , (175.5, single $ blackBackground)
        , (183.3, sceneTimeMangle tcpScene)
        , (197.1, single $ blackBackground)
        , (202.2, single $ centerWord "80")
        , (204.2, single $ blackBackground)
        , (225.4, single $ centerWord "<ol>")
        , (226.4, single $ blackBackground)
        , (239.9, single $ centerWord "X-ObsTCP")
        , (240.9, single $ blackBackground)
        , (241.3, single $ centerWord "<ol>")
        , (241.3, single $ blackBackground)
        , (247.3, single $ centerWord "www.google.com")
        , (248, single $ centerWord "209.85.173.104")
        , (250, single $ blackBackground)
        , (262.7, single $ centerWord "Apache")
        , (263.7, single $ centerWord "Firefox")
        , (264.7, single $ centerWord "lighttpd")
        , (266.7, single $ blackBackground)
        , (270, sceneTimeMangle endScene)
        ]

timeMangle :: Video -> Video
timeMangle = map (\(start, x) -> (start / 1.0, x))

sceneTimeMangle :: Scene -> Scene
sceneTimeMangle = map (\(start, x) -> (start / 1.0, x))

vidrn :: Video -> Double -> IO ()
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
  vidrn (timeMangle video) 277
