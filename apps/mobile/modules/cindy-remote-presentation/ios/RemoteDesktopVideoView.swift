import ExpoModulesCore
import AVKit
import WebRTC

/// Native media surface beneath the existing HTML input overlay. HTML supplies
/// its exact fitted/zoomed rectangle; pixels never cross the React bridge.
final class RemoteDesktopVideoView: ExpoView, AVPictureInPictureControllerDelegate,
  AVPictureInPictureSampleBufferPlaybackDelegate {
  let onMessage = EventDispatcher()
  private let display = AVSampleBufferDisplayLayer()
  private var pip: AVPictureInPictureController?
  private var receiver: RemoteDesktopReceiver?
  private var configuration: [String: Any]?
  private var retryTimer: Timer?
  private var stableTimer: Timer?
  private var retries = 0
  private var presenting = false
  var inlineVisible = true {
    didSet { updateInlineVisibility() }
  }
  private func updateInlineVisibility() {
    // Keep the source ready until PiP has actually started. Once detached,
    // hide the native source itself, not just its React parent's opacity.
    // The layer, receiver and PiP controller remain attached and alive.
    isHidden = !inlineVisible && presenting
  }
  private var wantsPresentation = false
  private var automaticPresentation = false
  private var restoreCompletion: ((Bool) -> Void)?
  private var restoreGeneration = 0
  private var restoringInterface = false
  private var lastCapability: Bool?
  private var latestFrame: RTCVideoFrame?
  private var pool: CVPixelBufferPool?
  private var poolSize = CGSize.zero
  private var backgroundObserver: NSObjectProtocol?
  private var foregroundObserver: NSObjectProtocol?
  private var pipObservation: NSKeyValueObservation?

  required init(appContext: AppContext? = nil) {
    super.init(appContext: appContext)
    clipsToBounds = true
    isUserInteractionEnabled = false
    display.videoGravity = .resizeAspect
    layer.addSublayer(display)
    if AVPictureInPictureController.isPictureInPictureSupported() {
      pip = AVPictureInPictureController(contentSource: .init(sampleBufferDisplayLayer: display, playbackDelegate: self))
      pip?.delegate = self
      pip?.requiresLinearPlayback = true
      // Armed only after the host has confirmed view-only presentation access.
      pip?.canStartPictureInPictureAutomaticallyFromInline = false
      pipObservation = pip?.observe(\.isPictureInPicturePossible, options: [.new]) { [weak self] _, _ in
        DispatchQueue.main.async { self?.reportCapability() }
      }
    }
    backgroundObserver = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in
      guard let self else { return }
      if !self.presenting && self.pip?.isPictureInPictureActive != true {
        if self.automaticPresentation || self.wantsPresentation {
          // AVKit may finish the automatic transition after background entry.
          // A failed transition must still release media without relying on JS.
          let current = self.receiver
          DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self, weak current] in
            guard let self, let current, self.receiver === current,
                  UIApplication.shared.applicationState != .active,
                  self.pip?.isPictureInPictureActive != true else { return }
            self.suspend()
          }
        } else { self.suspend() }
      }
    }
    foregroundObserver = NotificationCenter.default.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
      // JS may not receive the PiP stop callback until foreground. Replay the
      // actual native state so it cannot retain a stale presentation exemption.
      guard let self else { return }
      if let epoch = self.configuration?["epoch"] as? String {
        self.emit(["type": "presentation", "epoch": epoch, "active": self.presenting])
      }
      self.reportCapability()
    }
  }
  deinit {
    if let backgroundObserver { NotificationCenter.default.removeObserver(backgroundObserver) }
    if let foregroundObserver { NotificationCenter.default.removeObserver(foregroundObserver) }
    retryTimer?.invalidate()
    stableTimer?.invalidate()
    receiver?.stop()
  }
  override func didMoveToWindow() {
    super.didMoveToWindow()
    if window == nil { stop() }
  }
  func receive(_ message: [String: Any]) {
    let type = message["type"] as? String
    if type == "init" {
      stop()
      configuration = message
      retries = 0
      connect()
      return
    }
    guard let config = configuration, message["epoch"] as? String == config["epoch"] as? String else { return }
    switch type {
    case "stop": stop()
    case "pipPolicy":
      automaticPresentation = message["enabled"] as? Bool == true
      wantsPresentation = message["preparing"] as? Bool == true
      pip?.canStartPictureInPictureAutomaticallyFromInline = automaticPresentation
    case "restorePresentation":
      let completion = restoreCompletion
      restoreCompletion = nil
      completion?(window != nil)
    case "videoSettings":
      configuration?.merge(message) { _, new in new }
      retries = 0
      connect()
    case "nativeViewport":
      guard let x = message["x"] as? Double, let y = message["y"] as? Double,
            let width = message["width"] as? Double, let height = message["height"] as? Double,
            [x, y, width, height].allSatisfy({ $0.isFinite }), width > 0, height > 0 else { return }
      CATransaction.begin()
      CATransaction.setDisableActions(true)
      display.frame = CGRect(x: x, y: y, width: width, height: height)
      CATransaction.commit()
    case "presentation":
      if message["enabled"] as? Bool == true {
        guard let pip, pip.isPictureInPicturePossible, latestFrame != nil else {
          receiver?.post("presentationFailed"); return
        }
        wantsPresentation = true
        pip.startPictureInPicture()
      } else {
        wantsPresentation = false
        presenting = false
        pip?.stopPictureInPicture()
      }
    case "resume":
      if let latestFrame { render(latestFrame) }
      if receiver == nil { connect() }
      receiver?.post("presentation", ["active": presenting])
    default: receiver?.receive(message)
    }
  }
  private func connect() {
    retryTimer?.invalidate()
    stableTimer?.invalidate()
    stableTimer = nil
    receiver?.stop()
    receiver = nil
    guard let config = configuration, let epoch = config["epoch"] as? String,
          UIApplication.shared.applicationState == .active else { return }
    let current = RemoteDesktopReceiver(epoch: epoch, audio: config["audio"] as? Bool == true,
                                        trickle: config["trickleIce"] as? Bool == true,
                                        net: config["net"] as? [String: Any] ?? [:])
    receiver = current
    lastCapability = nil
    current.isPresenting = { [weak self] in self?.presenting == true && self?.pip?.isPictureInPictureActive == true }
    current.onFrame = { [weak self, weak current] frame in
      guard let self, let current, self.receiver === current else { return false }
      guard self.render(frame) else { return false }
      self.latestFrame = frame
      self.reportCapability()
      return true
    }
    current.emit = { [weak self, weak current] event in
      guard let self, let current, self.receiver === current else { return }
      self.emit(event)
      if event["type"] as? String == "streaming", self.stableTimer == nil {
        let stableMs = (config["net"] as? [String: Any])?["stableMs"] as? Double ?? 30_000
        self.stableTimer = Timer.scheduledTimer(withTimeInterval: stableMs / 1000, repeats: false) { [weak self, weak current] _ in
          guard let self, let current, self.receiver === current else { return }
          self.retries = 0
        }
      }
      if event["type"] as? String == "reconnecting" || event["type"] as? String == "fallback" {
        self.stableTimer?.invalidate()
        self.stableTimer = nil
      }
      if event["type"] as? String == "fallback" {
        self.wantsPresentation = false
        self.presenting = false
        self.pip?.stopPictureInPicture()
        self.receiver = nil
        let delays = (config["net"] as? [String: Any])?["retryMs"] as? [Double] ?? [1000, 3000, 8000]
        if event["retry"] as? Bool != false, self.retries < delays.count {
          let delay = delays[self.retries] / 1000
          self.retries += 1
          self.retryTimer = Timer.scheduledTimer(withTimeInterval: delay, repeats: false) { [weak self] _ in self?.connect() }
        }
      }
    }
    current.begin(fallbackServers: config["iceServers"] as? [[String: Any]] ?? [])
  }
  func sendInput(_ message: [String: Any]) -> Bool {
    guard !presenting, message["epoch"] as? String == configuration?["epoch"] as? String else { return false }
    return receiver?.sendInput(message) == true
  }
  private func emit(_ value: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: value),
          let json = String(data: data, encoding: .utf8) else { return }
    onMessage(["data": json])
  }
  private func reportCapability() {
    let supported = pip?.isPictureInPicturePossible == true && latestFrame != nil
    guard supported != lastCapability else { return }
    lastCapability = supported
    receiver?.post("pipCapability", ["supported": supported])
  }
  private func suspend() {
    let saved = configuration
    let current = receiver
    current?.post("presentation", ["active": false])
    current?.post("fallback", ["retry": false, "reason": "background"])
    // The synchronous fallback observer detaches receiver; retain the old owner
    // until its tracks, channel and pending callbacks have been explicitly stopped.
    current?.stop()
    stop()
    configuration = saved
  }
  private func stop() {
    // Stop pongs before asynchronous AVKit callbacks, even with JS suspended.
    presenting = false
    updateInlineVisibility()
    wantsPresentation = false
    automaticPresentation = false
    restoringInterface = false
    pip?.canStartPictureInPictureAutomaticallyFromInline = false
    let completion = restoreCompletion
    restoreCompletion = nil
    completion?(false)
    retryTimer?.invalidate()
    retryTimer = nil
    stableTimer?.invalidate()
    stableTimer = nil
    receiver?.stop()
    receiver = nil
    configuration = nil
    pip?.stopPictureInPicture()
    display.flushAndRemoveImage()
    latestFrame = nil
    pool = nil
  }
  @discardableResult private func render(_ frame: RTCVideoFrame) -> Bool {
    guard let buffer = pixelBuffer(frame) else { return false }
    var format: CMVideoFormatDescription?
    guard CMVideoFormatDescriptionCreateForImageBuffer(allocator: kCFAllocatorDefault, imageBuffer: buffer, formatDescriptionOut: &format) == noErr,
          let format else { return false }
    var timing = CMSampleTimingInfo(duration: .invalid, presentationTimeStamp: CMClockGetTime(CMClockGetHostTimeClock()), decodeTimeStamp: .invalid)
    var sample: CMSampleBuffer?
    guard CMSampleBufferCreateReadyWithImageBuffer(allocator: kCFAllocatorDefault, imageBuffer: buffer, formatDescription: format, sampleTiming: &timing, sampleBufferOut: &sample) == noErr,
          let sample else { return false }
    // Live remote desktop has no seekable timeline; display every decoded frame
    // immediately rather than accumulating latency behind presentation timestamps.
    if let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: true) {
      let entry = unsafeBitCast(CFArrayGetValueAtIndex(attachments, 0), to: CFMutableDictionary.self)
      CFDictionarySetValue(entry, Unmanaged.passUnretained(kCMSampleAttachmentKey_DisplayImmediately).toOpaque(), Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
    }
    if display.status == .failed { display.flush() }
    guard display.isReadyForMoreMediaData else { return false }
    display.enqueue(sample)
    return true
  }
  private func pixelBuffer(_ frame: RTCVideoFrame) -> CVPixelBuffer? {
    if let native = frame.buffer as? RTCCVPixelBuffer,
       native.width == CVPixelBufferGetWidth(native.pixelBuffer),
       native.height == CVPixelBufferGetHeight(native.pixelBuffer),
       native.cropX == 0, native.cropY == 0,
       native.cropWidth == native.width, native.cropHeight == native.height {
      return native.pixelBuffer
    }
    let source = frame.buffer.toI420()
    let width = Int(source.width), height = Int(source.height)
    let size = CGSize(width: width, height: height)
    if pool == nil || poolSize != size {
      poolSize = size
      let attributes: [String: Any] = [
        kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        kCVPixelBufferWidthKey as String: width, kCVPixelBufferHeightKey as String: height,
        kCVPixelBufferIOSurfacePropertiesKey as String: [:],
      ]
      CVPixelBufferPoolCreate(nil, nil, attributes as CFDictionary, &pool)
    }
    guard let pool else { return nil }
    var output: CVPixelBuffer?
    let limits = [kCVPixelBufferPoolAllocationThresholdKey as String: 4] as CFDictionary
    guard CVPixelBufferPoolCreatePixelBufferWithAuxAttributes(nil, pool, limits, &output) == kCVReturnSuccess,
          let output else { return nil }
    CVPixelBufferLockBaseAddress(output, [])
    defer { CVPixelBufferUnlockBaseAddress(output, []) }
    guard let y = CVPixelBufferGetBaseAddressOfPlane(output, 0), let uv = CVPixelBufferGetBaseAddressOfPlane(output, 1) else { return nil }
    for row in 0..<height {
      memcpy(y.advanced(by: row * CVPixelBufferGetBytesPerRowOfPlane(output, 0)), source.dataY.advanced(by: row * Int(source.strideY)), width)
    }
    for row in 0..<((height + 1) / 2) {
      let destination = uv.advanced(by: row * CVPixelBufferGetBytesPerRowOfPlane(output, 1)).assumingMemoryBound(to: UInt8.self)
      let u = source.dataU.advanced(by: row * Int(source.strideU))
      let v = source.dataV.advanced(by: row * Int(source.strideV))
      for column in 0..<((width + 1) / 2) {
        destination[column * 2] = u[column]
        destination[column * 2 + 1] = v[column]
      }
    }
    return output
  }
  func pictureInPictureControllerWillStartPictureInPicture(_ controller: AVPictureInPictureController) {
    if automaticPresentation { wantsPresentation = true }
  }
  func pictureInPictureControllerDidStartPictureInPicture(_ controller: AVPictureInPictureController) {
    guard wantsPresentation, receiver != nil else { controller.stopPictureInPicture(); return }
    presenting = true
    updateInlineVisibility()
    receiver?.replyToViewChallenge()
    receiver?.post("presentation", ["active": true])
  }
  func pictureInPictureControllerWillStopPictureInPicture(_ controller: AVPictureInPictureController) {
    wantsPresentation = false
    presenting = false
  }
  func pictureInPictureControllerDidStopPictureInPicture(_ controller: AVPictureInPictureController) {
    updateInlineVisibility()
    receiver?.post("presentation", ["active": false])
    if UIApplication.shared.applicationState != .active && !restoringInterface { suspend() }
    restoringInterface = false
  }
  func pictureInPictureController(_ controller: AVPictureInPictureController, failedToStartPictureInPictureWithError error: Error) {
    wantsPresentation = false
    presenting = false
    updateInlineVisibility()
    receiver?.post("presentationFailed")
  }
  func pictureInPictureController(_ controller: AVPictureInPictureController, restoreUserInterfaceForPictureInPictureStopWithCompletionHandler completionHandler: @escaping (Bool) -> Void) {
    restoreCompletion?(false)
    restoreCompletion = completionHandler
    restoringInterface = true
    restoreGeneration += 1
    let generation = restoreGeneration
    receiver?.post("presentationRestore", ["inlineVisible": inlineVisible, "sourceHidden": isHidden])
    DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
      guard let self, self.restoreGeneration == generation else { return }
      let completion = self.restoreCompletion
      self.restoreCompletion = nil
      completion?(false)
    }
  }
  func pictureInPictureController(_ controller: AVPictureInPictureController, setPlaying playing: Bool) {
    if !playing { wantsPresentation = false; presenting = false; controller.stopPictureInPicture() }
  }
  func pictureInPictureControllerTimeRangeForPlayback(_ controller: AVPictureInPictureController) -> CMTimeRange {
    CMTimeRange(start: .negativeInfinity, duration: .positiveInfinity)
  }
  func pictureInPictureControllerIsPlaybackPaused(_ controller: AVPictureInPictureController) -> Bool { false }
  func pictureInPictureController(_ controller: AVPictureInPictureController, didTransitionToRenderSize newRenderSize: CMVideoDimensions) {}
  func pictureInPictureController(_ controller: AVPictureInPictureController, skipByInterval skipInterval: CMTime, completion: @escaping () -> Void) { completion() }
}
