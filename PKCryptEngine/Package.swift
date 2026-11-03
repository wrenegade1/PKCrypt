// swift-tools-version: 6.0
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import PackageDescription

let package = Package(
    name: "PKCryptEngine",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "PKCryptEngine", targets: ["PKCryptEngine"])
    ],
    targets: [
        // systemLibrary wrapping libsodium's audited, statically-linked archive.
        // Headers are exposed via module.modulemap; the archive itself is linked
        // (never a dylib) via the absolute archive path below (Phase-1 D-02 proof:
        // otool -L shows no sodium dylib, nm shows T _sodium_init in the binary).
        .systemLibrary(
            name: "CSodium",
            path: "Sources/CSodium"
        ),
        .target(
            name: "PKCryptEngine",
            dependencies: ["CSodium"],
            linkerSettings: [
                .unsafeFlags(["/opt/homebrew/lib/libsodium.a"])
            ]
        ),
        .testTarget(
            name: "PKCryptEngineTests",
            dependencies: ["PKCryptEngine"],
            // Test keys and containers are generated per run
            // (Scripts/make_test_fixtures.py); none are committed.
            linkerSettings: [
                .unsafeFlags(["/opt/homebrew/lib/libsodium.a"])
            ]
        )
    ]
)
