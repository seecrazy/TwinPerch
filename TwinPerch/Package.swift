// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TwinPerchKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "TwinPerchKit", targets: ["TwinPerchKit"]),
        .library(name: "TwinPerchAppCore", targets: ["TwinPerchAppCore"]),
    ],
    targets: [
        .target(name: "TwinPerchKit"),
        .target(name: "TwinPerchAppCore", dependencies: ["TwinPerchKit"]),
        .executableTarget(name: "TwinPerchAppDemo", dependencies: ["TwinPerchAppCore"]),
        .testTarget(
            name: "TwinPerchKitTests",
            dependencies: ["TwinPerchKit", "TwinPerchAppCore"],
            resources: [.copy("Fixtures/vectors.json")]
        )
    ]
)
