import PackageDescription

let package = Package(
    name: "Ocelot",
    dependencies: [
    .Package(url: "https://github.com/OpenKitten/Cheetah.git", majorVersion: 1),
    .Package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", versions: Version(0, 6, 9) ..< Version(0, 7, 0))
    ]
)
