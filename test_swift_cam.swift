import AVFoundation

let session = AVCaptureDevice.DiscoverySession(
    deviceTypes: [.builtInWideAngleCamera, .externalUnknown],
    mediaType: .video,
    position: .unspecified
)

for (index, device) in session.devices.enumerated() {
    print("[\(index)] \(device.localizedName)")
}
