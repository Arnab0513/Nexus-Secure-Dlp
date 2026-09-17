// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "NexusSwift",
    platforms: [
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "NexusSwift",
            targets: ["NexusSwift"]
        )
    ],
    targets: [
        .target(
            name: "NexusSwift",
            path: ".",
            sources: ["test_swift_cam.swift"]
        )
    ]
)
