// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.


import PackageDescription

let package = Package(
    name: "Ocelot",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "Ocelot",
            targets: ["Ocelot"]),
    ],
    dependencies: [
        .package(url: "https://github.com/OpenKitten/Cheetah.git", from: "2.0.0"),
        .package(url: "https://github.com/OpenKitten/CryptoKitten.git", from: Version(0,2,1))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "Ocelot",
            dependencies: ["Cheetah", "CryptoKitten"]),
        .testTarget(
            name: "OcelotTests",
            dependencies: ["Ocelot"]),
    ]
)
