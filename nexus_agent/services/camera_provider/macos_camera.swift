import Foundation
import AVFoundation
import CoreMedia
import CoreImage

class CameraManager: NSObject, AVCapturePhotoCaptureDelegate {
    var session: AVCaptureSession?
    var photoOutput: AVCapturePhotoOutput?
    var captureFinished = false
    var error: String?
    var outputPath: String?
    
    func discoverCameras() -> [AVCaptureDevice] {
        let discoverySession = AVCaptureDevice.DiscoverySession(
            deviceTypes: [.builtInWideAngleCamera, .external],
            mediaType: .video,
            position: .unspecified
        )
        return discoverySession.devices
    }
    
    func listCameras() {
        let devices = discoverCameras()
        print("Available cameras:")
        for (index, device) in devices.enumerated() {
            let isContinuity = device.localizedName.lowercased().contains("iphone") || 
                               device.localizedName.lowercased().contains("continuity") ||
                               device.manufacturer.lowercased().contains("apple") && device.modelID.lowercased().contains("iphone")
                               
            let isBuiltin = device.deviceType == .builtInWideAngleCamera || 
                            device.localizedName.lowercased().contains("built-in") || 
                            device.localizedName.lowercased().contains("facetime")
                            
            print("--------------------------------")
            print("Camera")
            print("Name: \(device.localizedName)")
            print("Manufacturer: \(device.manufacturer)")
            print("Model ID: \(device.modelID)")
            print("Unique ID: \(device.uniqueID)")
            print("Device Type: \(device.deviceType.rawValue)")
            print("Position: \(device.position.rawValue)")
            print("Continuity/iPhone: \(isContinuity ? "YES" : "NO")")
            print("Built-in: \(isBuiltin ? "YES" : "NO")")
        }
        print("--------------------------------")
    }
    
    func capturePhoto(uniqueID: String, to output: String) {
        self.outputPath = output
        let devices = discoverCameras()
        guard let device = devices.first(where: { $0.uniqueID == uniqueID }) else {
            print("ERROR: Device with Unique ID \(uniqueID) not found.")
            exit(1)
        }
        
        do {
            let input = try AVCaptureDeviceInput(device: device)
            self.session = AVCaptureSession()
            self.session?.sessionPreset = .photo
            
            if self.session!.canAddInput(input) {
                self.session!.addInput(input)
            } else {
                print("ERROR: Cannot add input for device.")
                exit(1)
            }
            
            self.photoOutput = AVCapturePhotoOutput()
            if self.session!.canAddOutput(self.photoOutput!) {
                self.session!.addOutput(self.photoOutput!)
            } else {
                print("ERROR: Cannot add photo output.")
                exit(1)
            }
            
            self.session!.startRunning()
            
            // Allow camera to warm up
            Thread.sleep(forTimeInterval: 0.3)
            
            let settings = AVCapturePhotoSettings()
            self.photoOutput?.capturePhoto(with: settings, delegate: self)
            
            // Run loop until capture finishes
            let loop = RunLoop.current
            while !self.captureFinished && loop.run(mode: .default, before: Date(timeIntervalSinceNow: 0.1)) {}
            
            self.session!.stopRunning()
            
            if let err = self.error {
                print("ERROR: \(err)")
                exit(1)
            }
            print("SUCCESS: Image captured to \(output)")
            
        } catch {
            print("ERROR: \(error.localizedDescription)")
            exit(1)
        }
    }
    
    func photoOutput(_ output: AVCapturePhotoOutput, didFinishProcessingPhoto photo: AVCapturePhoto, error: Error?) {
        if let error = error {
            self.error = error.localizedDescription
            self.captureFinished = true
            return
        }
        
        guard let data = photo.fileDataRepresentation() else {
            self.error = "Could not get photo data."
            self.captureFinished = true
            return
        }
        
        let url = URL(fileURLWithPath: self.outputPath!)
        do {
            try data.write(to: url)
        } catch {
            self.error = "Failed to write photo to disk: \(error.localizedDescription)"
        }
        
        self.captureFinished = true
    }
    func captureBuiltin(to output: String) {
        self.outputPath = output
        let devices = discoverCameras()
        
        // Find builtin
        var selectedDevice: AVCaptureDevice? = nil
        for device in devices {
            let isContinuity = device.localizedName.lowercased().contains("iphone") || 
                               device.localizedName.lowercased().contains("continuity") ||
                               device.manufacturer.lowercased().contains("apple") && device.modelID.lowercased().contains("iphone")
                               
            let isBuiltin = device.deviceType == .builtInWideAngleCamera || 
                            device.localizedName.lowercased().contains("built-in") || 
                            device.localizedName.lowercased().contains("facetime")
                            
            if !isContinuity && isBuiltin {
                selectedDevice = device
                print("[CAMERA] Selected built-in MacBook camera:\n    \(device.localizedName)")
                break
            }
        }
        
        if selectedDevice == nil {
            print("ERROR: Built-in MacBook camera not found.")
            exit(1)
        }
        
        capturePhoto(uniqueID: selectedDevice!.uniqueID, to: output)
    }
}

let args = CommandLine.arguments
if args.count < 2 {
    print("Usage: swift macos_camera.swift --list | --capture <unique_id> <output_path> | --capture-builtin <output_path>")
    exit(1)
}

let manager = CameraManager()

if args[1] == "--list" {
    manager.listCameras()
} else if args[1] == "--capture-builtin" {
    if args.count < 3 {
        print("Usage: swift macos_camera.swift --capture-builtin <output_path>")
        exit(1)
    }
    manager.captureBuiltin(to: args[2])
} else if args[1] == "--capture" {
    if args.count < 4 {
        print("Usage: swift macos_camera.swift --capture <unique_id> <output_path>")
        exit(1)
    }
    manager.capturePhoto(uniqueID: args[2], to: args[3])
} else {
    print("Unknown command.")
    exit(1)
}
