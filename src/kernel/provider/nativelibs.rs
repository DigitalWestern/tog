//! Pinned, relocatable native libraries for Linux builds (kernel provider
//! layer): the set both Python sdist builds and npm install scripts mount.
//!
//! The table below is a deliberately boring conda-forge closure. It is not a
//! solver: the records, including their sha256 values, were selected once
//! from conda-forge's linux-64 and noarch repodata and are immutable inputs
//! to the native-libs object. macOS has no native pin yet and fails before it
//! touches the store or network.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{download_verified_held, Digest as FetchDigest};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::store::Store;
use crate::kernel::types::Identity;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use zip::ZipArchive;

pub const NATIVE_LIBS_VERSION: &str = "3";
const CONDA_BASE: &str = "https://conda.anaconda.org/conda-forge";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativePackage {
    pub name: &'static str,
    pub version: &'static str,
    pub build: &'static str,
    pub subdir: &'static str,
    pub filename: &'static str,
    pub sha256: &'static str,
}

impl NativePackage {
    pub fn url(self) -> String {
        format!("{CONDA_BASE}/{}/{}", self.subdir, self.filename)
    }
}

// Pinned from conda-forge linux-64/noarch repodata.json at pin time.
// The repodata snapshot contains these packages as tar.bz2 records. Keep
// noarch records in the closure because Cairo's font metapackage requires
// them; the platform-specific records remain linux-64.
pub const LINUX_NATIVE_PACKAGES: &[NativePackage] = &[
    NativePackage {
        name: "_libgcc_mutex",
        version: "0.1",
        build: "conda_forge",
        subdir: "linux-64",
        filename: "_libgcc_mutex-0.1-conda_forge.tar.bz2",
        sha256: "fe51de6107f9edc7aa4f786a70f4a883943bc9d39b3bb7307c04c41410990726",
    },
    NativePackage {
        name: "_openmp_mutex",
        version: "4.5",
        build: "2_gnu",
        subdir: "linux-64",
        filename: "_openmp_mutex-4.5-2_gnu.tar.bz2",
        sha256: "fbe2c5e56a653bebb982eda4876a9178aedfc2b545f25d0ce9c4c0b508253d22",
    },
    NativePackage {
        name: "bzip2",
        version: "1.0.8",
        build: "h7f98852_4",
        subdir: "linux-64",
        filename: "bzip2-1.0.8-h7f98852_4.tar.bz2",
        sha256: "cb521319804640ff2ad6a9f118d972ed76d86bea44e5626c09a13d38f562e1fa",
    },
    NativePackage {
        name: "ca-certificates",
        version: "2022.9.24",
        build: "ha878542_0",
        subdir: "linux-64",
        filename: "ca-certificates-2022.9.24-ha878542_0.tar.bz2",
        sha256: "058355034667e77d15389700f6b2364cc74efce0af63a418eacc1ce252458942",
    },
    NativePackage {
        name: "cairo",
        version: "1.16.0",
        build: "ha61ee94_1014",
        subdir: "linux-64",
        filename: "cairo-1.16.0-ha61ee94_1014.tar.bz2",
        sha256: "f062cf56e6e50d3ad4b425ebb3765ca9138c6ebc52e6a42d1377de8bc8d954f6",
    },
    NativePackage {
        name: "expat",
        version: "2.5.0",
        build: "h27087fc_0",
        subdir: "linux-64",
        filename: "expat-2.5.0-h27087fc_0.tar.bz2",
        sha256: "b44db0b92ae926b3fbbcd57c179fceb64fa11a9f9d09082e03be58b74dcad832",
    },
    NativePackage {
        name: "font-ttf-dejavu-sans-mono",
        version: "2.37",
        build: "hab24e00_0",
        subdir: "noarch",
        filename: "font-ttf-dejavu-sans-mono-2.37-hab24e00_0.tar.bz2",
        sha256: "58d7f40d2940dd0a8aa28651239adbf5613254df0f75789919c4e6762054403b",
    },
    NativePackage {
        name: "font-ttf-inconsolata",
        version: "3.000",
        build: "h77eed37_0",
        subdir: "noarch",
        filename: "font-ttf-inconsolata-3.000-h77eed37_0.tar.bz2",
        sha256: "c52a29fdac682c20d252facc50f01e7c2e7ceac52aa9817aaf0bb83f7559ec5c",
    },
    NativePackage {
        name: "font-ttf-source-code-pro",
        version: "2.038",
        build: "h77eed37_0",
        subdir: "noarch",
        filename: "font-ttf-source-code-pro-2.038-h77eed37_0.tar.bz2",
        sha256: "00925c8c055a2275614b4d983e1df637245e19058d79fc7dd1a93b8d9fb4b139",
    },
    NativePackage {
        name: "font-ttf-ubuntu",
        version: "0.83",
        build: "hab24e00_0",
        subdir: "noarch",
        filename: "font-ttf-ubuntu-0.83-hab24e00_0.tar.bz2",
        sha256: "470d5db54102bd51dbb0c5990324a2f4a0bc976faa493b22193338adb9882e2e",
    },
    NativePackage {
        name: "fontconfig",
        version: "2.14.1",
        build: "hc2a2eb6_0",
        subdir: "linux-64",
        filename: "fontconfig-2.14.1-hc2a2eb6_0.tar.bz2",
        sha256: "4594348401ccdb622b41692698f3701423e9a4e726b6b6efa818c3a1611b01f9",
    },
    NativePackage {
        name: "fonts-conda-ecosystem",
        version: "1",
        build: "0",
        subdir: "noarch",
        filename: "fonts-conda-ecosystem-1-0.tar.bz2",
        sha256: "a997f2f1921bb9c9d76e6fa2f6b408b7fa549edd349a77639c9fe7a23ea93e61",
    },
    NativePackage {
        name: "fonts-conda-forge",
        version: "1",
        build: "0",
        subdir: "noarch",
        filename: "fonts-conda-forge-1-0.tar.bz2",
        sha256: "53f23a3319466053818540bcdf2091f253cbdbab1e0e9ae7b9e509dcaa2a5e38",
    },
    NativePackage {
        name: "freetype",
        version: "2.12.1",
        build: "hca18f0e_0",
        subdir: "linux-64",
        filename: "freetype-2.12.1-hca18f0e_0.tar.bz2",
        sha256: "97325af03590d9f9cc7fcb35ad869fa409c51820b0c721bfc9fe7a6d058d0bb0",
    },
    NativePackage {
        name: "fribidi",
        version: "1.0.10",
        build: "h516909a_0",
        subdir: "linux-64",
        filename: "fribidi-1.0.10-h516909a_0.tar.bz2",
        sha256: "b619c1ec2c2b0951e23c683c6ca33de295183ee82f080e97eda68a7a7a955d85",
    },
    NativePackage {
        name: "gettext",
        version: "0.21.1",
        build: "h27087fc_0",
        subdir: "linux-64",
        filename: "gettext-0.21.1-h27087fc_0.tar.bz2",
        sha256: "4fcfedc44e4c9a053f0416f9fc6ab6ed50644fca3a761126dbd00d09db1f546a",
    },
    NativePackage {
        name: "glib",
        version: "2.74.1",
        build: "h6239696_1",
        subdir: "linux-64",
        filename: "glib-2.74.1-h6239696_1.tar.bz2",
        sha256: "bc3f1d84e976a62ae8388e3b44f260d867beb7a307c18147048a8301a3c12e47",
    },
    NativePackage {
        name: "glib-tools",
        version: "2.74.1",
        build: "h6239696_1",
        subdir: "linux-64",
        filename: "glib-tools-2.74.1-h6239696_1.tar.bz2",
        sha256: "029533e2e1cb03a80ae07a0a1a6bdd76b524e8f551d82e832a4d846a77b615c9",
    },
    NativePackage {
        name: "graphite2",
        version: "1.3.13",
        build: "he1b5a44_1001",
        subdir: "linux-64",
        filename: "graphite2-1.3.13-he1b5a44_1001.tar.bz2",
        sha256: "5d6a65066c66e3df8119a042cdd242359323e9269a94c722f05db74e0ddcb77c",
    },
    NativePackage {
        name: "harfbuzz",
        version: "5.3.0",
        build: "h418a68e_0",
        subdir: "linux-64",
        filename: "harfbuzz-5.3.0-h418a68e_0.tar.bz2",
        sha256: "57c6ae03c3e70fe7cd28b9e5f27ee470181aef5426f6796a52bc591cfe473183",
    },
    NativePackage {
        name: "icu",
        version: "70.1",
        build: "h27087fc_0",
        subdir: "linux-64",
        filename: "icu-70.1-h27087fc_0.tar.bz2",
        sha256: "1d7950f3be4637ab915d886304e57731d39a41ab705ffc95c4681655c459374a",
    },
    NativePackage {
        name: "ld_impl_linux-64",
        version: "2.39",
        build: "hc81fddc_0",
        subdir: "linux-64",
        filename: "ld_impl_linux-64-2.39-hc81fddc_0.tar.bz2",
        sha256: "a41140cb2a85048eba89dcf6cc8267e673bf40ce2108534eda1531b9f939fe82",
    },
    NativePackage {
        name: "libffi",
        version: "3.4.2",
        build: "h7f98852_5",
        subdir: "linux-64",
        filename: "libffi-3.4.2-h7f98852_5.tar.bz2",
        sha256: "ab6e9856c21709b7b517e940ae7028ae0737546122f83c2aa5d692860c3b149e",
    },
    NativePackage {
        name: "libgcc-ng",
        version: "12.2.0",
        build: "h65d4601_19",
        subdir: "linux-64",
        filename: "libgcc-ng-12.2.0-h65d4601_19.tar.bz2",
        sha256: "f3899c26824cee023f1e360bd0859b0e149e2b3e8b1668bc6dd04bfc70dcd659",
    },
    NativePackage {
        name: "libglib",
        version: "2.74.1",
        build: "h606061b_1",
        subdir: "linux-64",
        filename: "libglib-2.74.1-h606061b_1.tar.bz2",
        sha256: "3cbad3d63cff2dd9ac1dc9cce54fd3d657f3aff53df41bfe5bae9d760562a5af",
    },
    NativePackage {
        name: "libgomp",
        version: "12.2.0",
        build: "h65d4601_19",
        subdir: "linux-64",
        filename: "libgomp-12.2.0-h65d4601_19.tar.bz2",
        sha256: "81a76d20cfdee9fe0728b93ef057ba93494fd1450d42bc3717af4e468235661e",
    },
    NativePackage {
        name: "libiconv",
        version: "1.17",
        build: "h166bdaf_0",
        subdir: "linux-64",
        filename: "libiconv-1.17-h166bdaf_0.tar.bz2",
        sha256: "6a81ebac9f1aacdf2b4f945c87ad62b972f0f69c8e0981d68e111739e6720fd7",
    },
    NativePackage {
        name: "libnsl",
        version: "2.0.0",
        build: "h7f98852_0",
        subdir: "linux-64",
        filename: "libnsl-2.0.0-h7f98852_0.tar.bz2",
        sha256: "32f4fb94d99946b0dabfbbfd442b25852baf909637f2eed1ffe3baea15d02aad",
    },
    NativePackage {
        name: "libpng",
        version: "1.6.38",
        build: "h753d276_0",
        subdir: "linux-64",
        filename: "libpng-1.6.38-h753d276_0.tar.bz2",
        sha256: "422a544fbfc8d8bf43de4b2dc5c7c991294ad0e37b37439d8dbf740f07a75437",
    },
    NativePackage {
        name: "libsqlite",
        version: "3.40.0",
        build: "h753d276_0",
        subdir: "linux-64",
        filename: "libsqlite-3.40.0-h753d276_0.tar.bz2",
        sha256: "6008a0b914bd1a3510a3dba38eada93aa0349ebca3a21e5fa276833c8205bf49",
    },
    NativePackage {
        name: "libstdcxx-ng",
        version: "12.2.0",
        build: "h46fd767_19",
        subdir: "linux-64",
        filename: "libstdcxx-ng-12.2.0-h46fd767_19.tar.bz2",
        sha256: "0289e6a7b9a5249161a3967909e12dcfb4ab4475cdede984635d3fb65c606f08",
    },
    NativePackage {
        name: "libuuid",
        version: "2.32.1",
        build: "h7f98852_1000",
        subdir: "linux-64",
        filename: "libuuid-2.32.1-h7f98852_1000.tar.bz2",
        sha256: "54f118845498353c936826f8da79b5377d23032bcac8c4a02de2019e26c3f6b3",
    },
    NativePackage {
        name: "libxcb",
        version: "1.13",
        build: "h7f98852_1004",
        subdir: "linux-64",
        filename: "libxcb-1.13-h7f98852_1004.tar.bz2",
        sha256: "8d5d24cbeda9282dd707edd3156e5fde2e3f3fe86c802fa7ce08c8f1e803bfd9",
    },
    NativePackage {
        name: "libxml2",
        version: "2.10.3",
        build: "h7463322_0",
        subdir: "linux-64",
        filename: "libxml2-2.10.3-h7463322_0.tar.bz2",
        sha256: "b30713fb4477ff4f722280d956593e7e7a2cb705b7444dcc278de447432b43b1",
    },
    NativePackage {
        name: "libzlib",
        version: "1.2.13",
        build: "h166bdaf_4",
        subdir: "linux-64",
        filename: "libzlib-1.2.13-h166bdaf_4.tar.bz2",
        sha256: "22f3663bcf294d349327e60e464a51cd59664a71b8ed70c28a9f512d10bc77dd",
    },
    NativePackage {
        name: "ncurses",
        version: "6.3",
        build: "h27087fc_1",
        subdir: "linux-64",
        filename: "ncurses-6.3-h27087fc_1.tar.bz2",
        sha256: "b801e8cf4b2c9a30bce5616746c6c2a4e36427f045b46d9fc08a4ed40a9f7065",
    },
    NativePackage {
        name: "openssl",
        version: "3.0.7",
        build: "h166bdaf_0",
        subdir: "linux-64",
        filename: "openssl-3.0.7-h166bdaf_0.tar.bz2",
        sha256: "67fc8e91186ada002682bdd125e1ceece884ba309c68e9c5c981e8412196d226",
    },
    NativePackage {
        name: "pango",
        version: "1.50.11",
        build: "h382ae3d_0",
        subdir: "linux-64",
        filename: "pango-1.50.11-h382ae3d_0.tar.bz2",
        sha256: "735a19c98460b640ad7f2eb7dc4a9cebac8263f0ca27ba74f3fb99bcf01b1997",
    },
    NativePackage {
        name: "pcre2",
        version: "10.40",
        build: "hc3806b6_0",
        subdir: "linux-64",
        filename: "pcre2-10.40-hc3806b6_0.tar.bz2",
        sha256: "7a29ec847556eed4faa1646010baae371ced69059a4ade43851367a076d6108a",
    },
    NativePackage {
        name: "pixman",
        version: "0.40.0",
        build: "h36c2ea0_0",
        subdir: "linux-64",
        filename: "pixman-0.40.0-h36c2ea0_0.tar.bz2",
        sha256: "6a0630fff84b5a683af6185a6c67adc8bdfa2043047fcb251add0d352ef60e79",
    },
    NativePackage {
        name: "pkg-config",
        version: "0.29.2",
        build: "h516909a_1008",
        subdir: "linux-64",
        filename: "pkg-config-0.29.2-h516909a_1008.tar.bz2",
        sha256: "a1b9d72f2f49293ebe61e080c2872edc1d6b9396e037bb7d634cac0aad43e20b",
    },
    NativePackage {
        name: "pthread-stubs",
        version: "0.4",
        build: "h36c2ea0_1001",
        subdir: "linux-64",
        filename: "pthread-stubs-0.4-h36c2ea0_1001.tar.bz2",
        sha256: "67c84822f87b641d89df09758da498b2d4558d47b920fd1d3fe6d3a871e000ff",
    },
    NativePackage {
        name: "python",
        version: "3.11.0",
        build: "ha86cf86_0_cpython",
        subdir: "linux-64",
        filename: "python-3.11.0-ha86cf86_0_cpython.tar.bz2",
        sha256: "60cd4d442f851efd46640f7c212110721921f0ee9c664ea0d1c339567a82d7a3",
    },
    NativePackage {
        name: "readline",
        version: "8.1.2",
        build: "h0f457ee_0",
        subdir: "linux-64",
        filename: "readline-8.1.2-h0f457ee_0.tar.bz2",
        sha256: "f5f383193bdbe01c41cb0d6f99fec68e820875e842e6e8b392dbe1a9b6c43ed8",
    },
    NativePackage {
        name: "tk",
        version: "8.6.12",
        build: "h27826a3_0",
        subdir: "linux-64",
        filename: "tk-8.6.12-h27826a3_0.tar.bz2",
        sha256: "032fd769aad9d4cad40ba261ab222675acb7ec951a8832455fce18ef33fa8df0",
    },
    NativePackage {
        name: "tzdata",
        version: "2022f",
        build: "h191b570_0",
        subdir: "noarch",
        filename: "tzdata-2022f-h191b570_0.tar.bz2",
        sha256: "419eaff0d20f418974ca27a40bc871bbe48217dba05936f147a574eb5f079005",
    },
    NativePackage {
        name: "xorg-kbproto",
        version: "1.0.7",
        build: "h7f98852_1002",
        subdir: "linux-64",
        filename: "xorg-kbproto-1.0.7-h7f98852_1002.tar.bz2",
        sha256: "e90b0a6a5d41776f11add74aa030f789faf4efd3875c31964d6f9cfa63a10dd1",
    },
    NativePackage {
        name: "xorg-libice",
        version: "1.0.10",
        build: "h7f98852_0",
        subdir: "linux-64",
        filename: "xorg-libice-1.0.10-h7f98852_0.tar.bz2",
        sha256: "f15ce1dff16823888bcc2be1738aadcb36699be1e2dd2afa347794c7ec6c1587",
    },
    NativePackage {
        name: "xorg-libsm",
        version: "1.2.3",
        build: "hd9c2040_1000",
        subdir: "linux-64",
        filename: "xorg-libsm-1.2.3-hd9c2040_1000.tar.bz2",
        sha256: "bdb350539521ddc1f30cc721b6604eced8ef72a0ec146e378bfe89e2be17ab35",
    },
    NativePackage {
        name: "xorg-libx11",
        version: "1.7.2",
        build: "h7f98852_0",
        subdir: "linux-64",
        filename: "xorg-libx11-1.7.2-h7f98852_0.tar.bz2",
        sha256: "ec4641131e3afcb4b34614a5fa298efb34f54c2b2960bf9a73a8d202140d47c4",
    },
    NativePackage {
        name: "xorg-libxau",
        version: "1.0.9",
        build: "h7f98852_0",
        subdir: "linux-64",
        filename: "xorg-libxau-1.0.9-h7f98852_0.tar.bz2",
        sha256: "9e9b70c24527289ac7ae31925d1eb3b0c1e9a78cb7b8f58a3110cc8bbfe51c26",
    },
    NativePackage {
        name: "xorg-libxdmcp",
        version: "1.1.3",
        build: "h7f98852_0",
        subdir: "linux-64",
        filename: "xorg-libxdmcp-1.1.3-h7f98852_0.tar.bz2",
        sha256: "4df7c5ee11b8686d3453e7f3f4aa20ceef441262b49860733066c52cfd0e4a77",
    },
    NativePackage {
        name: "xorg-libxext",
        version: "1.3.4",
        build: "h7f98852_1",
        subdir: "linux-64",
        filename: "xorg-libxext-1.3.4-h7f98852_1.tar.bz2",
        sha256: "cf47ccbf49d46189d7bdadeac1387c826be82deb92ce6badbb03baae4b67ed26",
    },
    NativePackage {
        name: "xorg-libxrender",
        version: "0.9.10",
        build: "h7f98852_1003",
        subdir: "linux-64",
        filename: "xorg-libxrender-0.9.10-h7f98852_1003.tar.bz2",
        sha256: "7d907ed9e2ec5af5d7498fb3ab744accc298914ae31497ab6dcc6ef8bd134d00",
    },
    NativePackage {
        name: "xorg-renderproto",
        version: "0.11.1",
        build: "h7f98852_1002",
        subdir: "linux-64",
        filename: "xorg-renderproto-0.11.1-h7f98852_1002.tar.bz2",
        sha256: "38942930f233d1898594dd9edf4b0c0786f3dbc12065a0c308634c37fd936034",
    },
    NativePackage {
        name: "xorg-xextproto",
        version: "7.3.0",
        build: "h7f98852_1002",
        subdir: "linux-64",
        filename: "xorg-xextproto-7.3.0-h7f98852_1002.tar.bz2",
        sha256: "d45c4d1c8372c546711eb3863c76d899d03a67c3edb3b5c2c46c9492814cbe03",
    },
    NativePackage {
        name: "xorg-xproto",
        version: "7.0.31",
        build: "h7f98852_1007",
        subdir: "linux-64",
        filename: "xorg-xproto-7.0.31-h7f98852_1007.tar.bz2",
        sha256: "f197bb742a17c78234c24605ad1fe2d88b1d25f332b75d73e5ba8cf8fbc2a10d",
    },
    NativePackage {
        name: "xz",
        version: "5.2.6",
        build: "h166bdaf_0",
        subdir: "linux-64",
        filename: "xz-5.2.6-h166bdaf_0.tar.bz2",
        sha256: "03a6d28ded42af8a347345f82f3eebdd6807a08526d47899a42d62d319609162",
    },
    NativePackage {
        name: "zlib",
        version: "1.2.13",
        build: "h166bdaf_4",
        subdir: "linux-64",
        filename: "zlib-1.2.13-h166bdaf_4.tar.bz2",
        sha256: "282ce274ebe6da1fbd52efbb61bd5a93dec0365b14d64566e6819d1691b75300",
    },
];

#[derive(Debug, Clone)]
pub struct NativeLibSet {
    pub id: String,
    pub path: PathBuf,
    pub platform: Platform,
    pub manifest_sha256: String,
}

pub fn packages(platform: Platform) -> io::Result<&'static [NativePackage]> {
    match platform {
        Platform::X86_64UnknownLinuxGnu => Ok(LINUX_NATIVE_PACKAGES),
        Platform::Aarch64AppleDarwin => Err(no_pin("native library set", platform)),
    }
}

pub fn manifest_sha256(platform: Platform) -> io::Result<String> {
    let mut manifest = String::new();
    for p in packages(platform)? {
        manifest.push_str(p.name);
        manifest.push('\t');
        manifest.push_str(p.version);
        manifest.push('\t');
        manifest.push_str(p.build);
        manifest.push('\t');
        manifest.push_str(p.subdir);
        manifest.push('\t');
        manifest.push_str(p.filename);
        manifest.push('\t');
        manifest.push_str(p.sha256);
        manifest.push('\n');
    }
    Ok(hex::encode(Sha256::digest(manifest.as_bytes())))
}

fn identity(store: &Store, platform: Platform) -> io::Result<Identity> {
    let store_root = store.root.canonicalize()?.to_string_lossy().into_owned();
    Ok(Identity {
        kind: "native-libs".into(),
        name: "libset".into(),
        version: NATIVE_LIBS_VERSION.into(),
        inputs: BTreeMap::from([
            ("platform".into(), platform.triple().into()),
            ("manifest_sha256".into(), manifest_sha256(platform)?),
            ("store_root".into(), store_root),
        ]),
    })
}

#[cfg(test)]
pub fn live_identity_for_test(store: &Store, platform: Platform) -> io::Result<Identity> {
    identity(store, platform)
}

/// Return the object id for the pinned native library set without realizing
/// it. The canonical store root, manifest, and platform are identity inputs.
pub fn object_id_for(store: &Store, platform: Platform) -> io::Result<String> {
    Ok(identity(store, platform)?.object_id())
}

/// Realize the pinned native library set. The caller has installed the
/// object-kind rows (`tailors::install_kinds`), as every realization entry
/// point does before it can publish.
pub fn ensure_native_libs(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
) -> io::Result<NativeLibSet> {
    crate::kernel::platform::require_host(platform, "native library set")?;
    let identity = identity(store, platform)?;
    let id = identity.object_id();
    let object = store.object_path(&id);
    let manifest_sha256 = identity.inputs["manifest_sha256"].clone();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        validate_layout(&object)?;
        return Ok(NativeLibSet {
            id,
            path: object,
            platform,
            manifest_sha256,
        });
    }

    let work = store.stage_with_activity(activity)?;
    let package_work = work.join("packages");
    fs::create_dir_all(&package_work)?;
    let packages = packages(platform)?;
    let result = realize_staged(store, activity, &work, &package_work, &object, packages);
    if let Err(error) = result {
        let _ = crate::kernel::store::remove_tree(&work);
        return Err(error);
    }
    validate_layout(&work)?;
    let mut deps = crate::kernel::store::ObjectDeps::new();
    for package in packages {
        deps.cache_digest(FetchDigest::sha256(package.sha256)?);
    }
    let (object, _) =
        store.commit_with_activity_and_deps(activity, &identity, &work, &[], &deps)?;
    validate_layout(&object)?;
    Ok(NativeLibSet {
        id,
        path: object,
        platform,
        manifest_sha256,
    })
}

fn realize_staged(
    store: &Store,
    activity: &StoreActivity,
    work: &Path,
    package_work: &Path,
    object: &Path,
    packages: &[NativePackage],
) -> io::Result<()> {
    let mut placeholders = Vec::new();
    for (index, package) in packages.iter().enumerate() {
        let archive = download_verified_held(store, activity, &package.url(), package.sha256)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("fetch native package {}: {e}", package.filename),
                )
            })?;
        let package_root = package_work.join(format!("{index}-payload"));
        let info_root = package_work.join(format!("{index}-info"));
        fs::create_dir_all(&package_root)?;
        fs::create_dir_all(&info_root)?;
        extract_package(activity, &archive, package, &package_root, &info_root)?;
        let mut package_placeholders = prefix_placeholders(&info_root)?;
        package_placeholders.extend(discover_payload_placeholders(&package_root)?);
        package_placeholders.sort();
        package_placeholders.dedup();
        placeholders.extend(package_placeholders.iter().cloned());
        relocate_package(&package_root, &info_root, object, &package_placeholders)?;
        let info = package_root.join("info");
        if info.exists() {
            crate::kernel::store::remove_tree(&info)?;
        }
        merge_tree(&package_root, work).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("merge native package {}: {e}", package.name),
            )
        })?;
        crate::kernel::store::remove_tree(&package_root)?;
        crate::kernel::store::remove_tree(&info_root)?;
    }
    placeholders.sort();
    placeholders.dedup();
    scan_for_placeholders(work, &placeholders)?;
    Ok(())
}

fn validate_layout(root: &Path) -> io::Result<()> {
    for relative in ["bin/pkg-config", "include", "lib", "lib/pkgconfig/pango.pc"] {
        let path = root.join(relative);
        let valid = if relative == "bin/pkg-config" {
            path.is_file()
        } else {
            path.is_dir() || path.is_file()
        };
        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("native library object is missing {relative}"),
            ));
        }
    }
    Ok(())
}

fn extract_package(
    activity: &StoreActivity,
    archive: &Path,
    package: &NativePackage,
    package_root: &Path,
    info_root: &Path,
) -> io::Result<()> {
    if archive.to_string_lossy().ends_with(".conda") || package.filename.ends_with(".conda") {
        extract_conda(activity, archive, package_root, info_root)
    } else {
        crate::kernel::archive::extract_with_activity_and_options(
            activity,
            archive,
            package_root,
            &crate::kernel::archive::ExtractOptions::platform_build(0),
            crate::kernel::archive::Compression::Bzip2,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("extract {}: {e}", package.filename)))?;
        if package_root.join("info").is_dir() {
            // Keep metadata separate from payload so it cannot leave the
            // build prefix in the committed object.
            fs::rename(package_root.join("info"), info_root.join("info"))?;
        }
        Ok(())
    }
}

fn extract_conda(
    activity: &StoreActivity,
    archive: &Path,
    package_root: &Path,
    info_root: &Path,
) -> io::Result<()> {
    let file = File::open(archive)?;
    let mut zip = ZipArchive::new(file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read {} as .conda zip: {e}", archive.display()),
        )
    })?;
    let mut pkg = None;
    let mut info = None;
    for index in 0..zip.len() {
        let entry = zip.by_index(index).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("read .conda entry {index}: {e}"),
            )
        })?;
        let name = entry.name().to_string();
        if name.starts_with("pkg-") && name.ends_with(".tar.zst") {
            pkg = Some(name);
        } else if name.starts_with("info-") && name.ends_with(".tar.zst") {
            info = Some(name);
        }
    }
    let pkg = pkg.ok_or_else(|| invalid_conda("missing pkg-*.tar.zst"))?;
    let info = info.ok_or_else(|| invalid_conda("missing info-*.tar.zst"))?;
    let pkg_zst = package_root.with_extension("pkg.tar.zst");
    let info_zst = info_root.with_extension("info.tar.zst");
    unzip_member(archive, &pkg, &pkg_zst)?;
    unzip_member(archive, &info, &info_zst)?;
    let pkg_tar = pkg_zst.with_extension("tar");
    let info_tar = info_zst.with_extension("tar");
    zstd_decompress(activity, &pkg_zst, &pkg_tar)?;
    zstd_decompress(activity, &info_zst, &info_tar)?;
    extract_tar(activity, &pkg_tar, package_root)?;
    extract_tar(activity, &info_tar, info_root)?;
    for path in [pkg_zst, info_zst, pkg_tar, info_tar] {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

fn unzip_member(archive: &Path, member: &str, destination: &Path) -> io::Result<()> {
    let file = File::open(archive)?;
    let mut zip = ZipArchive::new(file).map_err(|e| invalid_conda(format!("read zip: {e}")))?;
    let mut entry = zip
        .by_name(member)
        .map_err(|e| invalid_conda(format!("read {member}: {e}")))?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    fs::write(destination, bytes)
}

fn zstd_decompress(activity: &StoreActivity, input: &Path, output: &Path) -> io::Result<()> {
    let program = ["/usr/bin/zstd", "/usr/local/bin/zstd", "/usr/bin/unzstd"]
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native .conda extraction needs zstd/unzstd",
            )
        })?;
    let mut command = Command::new(program);
    command
        .args(["-d", "-f", "-q", "-o"])
        .arg(output)
        .arg(input);
    let status = crate::kernel::supervise::local_status(&mut command, activity)?;
    if !status.success() {
        return Err(invalid_conda(format!(
            "zstd failed for {}",
            input.display()
        )));
    }
    Ok(())
}

fn extract_tar(activity: &StoreActivity, archive: &Path, destination: &Path) -> io::Result<()> {
    crate::kernel::archive::extract_with_activity_and_options(
        activity,
        archive,
        destination,
        &crate::kernel::archive::ExtractOptions::platform_build(0),
        crate::kernel::archive::Compression::None,
    )
    .map(|_| ())
    .map_err(|e| {
        invalid_conda(format!(
            "tar extraction failed for {}: {e}",
            archive.display()
        ))
    })
}

fn invalid_conda(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn prefix_placeholders(info_root: &Path) -> io::Result<Vec<String>> {
    let info = info_root.join("info");
    let mut placeholders = Vec::new();
    let paths = info.join("paths.json");
    if paths.is_file() {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&paths)?).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse {}: {e}", paths.display()),
            )
        })?;
        let entries = value["paths"].as_array().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} has no paths list", paths.display()),
            )
        })?;
        placeholders.extend(
            entries
                .iter()
                .filter_map(|entry| entry["prefix_placeholder"].as_str())
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
    }

    let has_prefix = info.join("has_prefix");
    if has_prefix.is_file() {
        for line in fs::read_to_string(&has_prefix)?.lines() {
            let mut parts = line.split_whitespace();
            let prefix = parts
                .next()
                .ok_or_else(|| invalid_conda("malformed info/has_prefix"))?;
            let _mode = parts
                .next()
                .ok_or_else(|| invalid_conda("malformed info/has_prefix"))?;
            let _relative = parts
                .next()
                .ok_or_else(|| invalid_conda("malformed info/has_prefix"))?;
            if parts.next().is_some() {
                return Err(invalid_conda("malformed info/has_prefix path"));
            }
            placeholders.push(prefix.to_owned());
        }
    }
    Ok(placeholders)
}

fn discover_payload_placeholders(root: &Path) -> io::Result<Vec<String>> {
    const MARKER: &[u8] = b"placehold_placehold";
    const BUILD_ARTIFACTS: &[u8] = b"/home/conda/feedstock_root/build_artifacts/";

    fn discover(bytes: &[u8], placeholders: &mut Vec<String>) {
        let mut string_start = 0;
        while string_start <= bytes.len() {
            let string_end = bytes[string_start..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|offset| string_start + offset)
                .unwrap_or(bytes.len());
            let string = &bytes[string_start..string_end];
            let mut marker_search = 0;
            while let Some(relative) = find_bytes(&string[marker_search..], MARKER) {
                let marker = marker_search + relative;
                let prefix_start = {
                    let mut start = None;
                    let mut search = 0;
                    while let Some(relative) = find_bytes(&string[search..marker], BUILD_ARTIFACTS)
                    {
                        let candidate = search + relative;
                        start = Some(candidate);
                        search = candidate + 1;
                    }
                    start.unwrap_or(marker)
                };
                let suffix_start = string[marker..]
                    .iter()
                    .position(|byte| *byte == b'/')
                    .map(|offset| marker + offset)
                    .unwrap_or(string.len());
                if suffix_start > prefix_start {
                    if let Ok(placeholder) =
                        std::str::from_utf8(&string[prefix_start..suffix_start])
                    {
                        placeholders.push(placeholder.to_owned());
                    }
                }
                // Skip the complete placeholder run. Looking for the next
                // marker inside the same run would produce shorter nested
                // candidates and attempt to replace the same bytes again.
                marker_search = suffix_start;
            }
            if string_end == bytes.len() {
                break;
            }
            string_start = string_end + 1;
        }
    }

    fn walk(path: &Path, placeholders: &mut Vec<String>) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                walk(&path, placeholders)?;
            } else if metadata.is_file() {
                discover(&fs::read(&path)?, placeholders);
            }
        }
        Ok(())
    }

    let mut placeholders = Vec::new();
    walk(root, &mut placeholders)?;
    placeholders.sort();
    placeholders.dedup();
    Ok(placeholders)
}

fn scan_for_placeholders(root: &Path, placeholders: &[String]) -> io::Result<()> {
    fn walk(root: &Path, path: &Path, placeholders: &[String]) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                walk(root, &path, placeholders)?;
            } else if metadata.is_file() {
                let bytes = fs::read(&path)?;
                if let Some(placeholder) = placeholders
                    .iter()
                    .find(|placeholder| find_bytes(&bytes, placeholder.as_bytes()).is_some())
                {
                    return Err(invalid_conda(format!(
                        "prefix placeholder {:?} survived relocation in {}",
                        placeholder,
                        path.strip_prefix(root).unwrap_or(&path).display()
                    )));
                }
                if find_bytes(&bytes, b"placehold_placehold").is_some()
                    || find_bytes(&bytes, b"_h_env_placehold").is_some()
                {
                    return Err(invalid_conda(format!(
                        "undeclared prefix placeholder survived relocation in {}",
                        path.strip_prefix(root).unwrap_or(&path).display()
                    )));
                }
            }
        }
        Ok(())
    }
    walk(root, root, placeholders)
}

fn replace_pkg_config_wrapper(package_root: &Path) -> io::Result<()> {
    let wrapper = package_root.join("bin/pkg-config");
    let binary = package_root.join("bin/pkg-config.bin");
    let Ok(metadata) = fs::symlink_metadata(&wrapper) else {
        return Ok(());
    };
    if !metadata.file_type().is_file() || !binary.is_file() {
        return Ok(());
    }
    let contents = fs::read(&wrapper)?;
    if !contents.starts_with(b"#!") {
        return Ok(());
    }
    // conda-forge's wrapper reconstructs PKG_CONFIG_LIBDIR from its build
    // prefix and /usr. Keep the real binary but preserve the caller's
    // already-isolated PKG_CONFIG_PATH/PKG_CONFIG_LIBDIR instead.
    fs::write(
        wrapper,
        b"#!/bin/sh\nexec \"$(dirname \"$0\")/pkg-config.bin\" \"$@\"\n",
    )
}

fn rewrite_remaining_prefixes(
    package_root: &Path,
    placeholders: &[String],
    object: &Path,
) -> io::Result<()> {
    fn walk(path: &Path, placeholders: &[String], object: &Path) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                walk(&path, placeholders, object)?;
            } else if metadata.is_file() {
                let mut bytes = fs::read(&path)?;
                for placeholder in placeholders {
                    if find_bytes(&bytes, placeholder.as_bytes()).is_none() {
                        continue;
                    }
                    if placeholder.starts_with("placehold") {
                        rewrite_prefix_file_with_target(
                            &path,
                            placeholder,
                            "$ORIGIN/..",
                            bytes.contains(&0),
                        )?;
                    } else {
                        rewrite_prefix_file(&path, placeholder, object, bytes.contains(&0))?;
                    }
                    bytes = fs::read(&path)?;
                }
            }
        }
        Ok(())
    }
    walk(package_root, placeholders, object)
}

fn relocate_package(
    package_root: &Path,
    info_root: &Path,
    object: &Path,
    placeholders: &[String],
) -> io::Result<()> {
    let info = info_root.join("info");
    let mut relocated = BTreeSet::new();
    let paths = info.join("paths.json");
    if paths.is_file() {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&paths)?).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse {}: {e}", paths.display()),
            )
        })?;
        let entries = value["paths"].as_array().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} has no paths list", paths.display()),
            )
        })?;
        for entry in entries {
            let relative = entry["_path"].as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} has a path without _path", paths.display()),
                )
            })?;
            let Some(prefix) = entry["prefix_placeholder"].as_str() else {
                continue;
            };
            let mode = entry["file_mode"].as_str().unwrap_or("text");
            if !relocated.insert(relative.to_owned()) {
                continue;
            }
            rewrite_prefix_file(
                &package_root.join(safe_relative(relative)?),
                prefix,
                object,
                mode == "binary",
            )?;
        }
    }

    // Older conda tar.bz2 records use info/has_prefix. It has the same
    // prefix/mode/path information and is kept as a compatibility fallback.
    let has_prefix = info.join("has_prefix");
    if has_prefix.is_file() {
        for line in fs::read_to_string(&has_prefix)?.lines() {
            let mut parts = line.split_whitespace();
            let prefix = parts
                .next()
                .ok_or_else(|| invalid_conda("malformed info/has_prefix"))?;
            let mode = parts
                .next()
                .ok_or_else(|| invalid_conda("malformed info/has_prefix"))?;
            let relative = parts
                .next()
                .ok_or_else(|| invalid_conda("malformed info/has_prefix"))?;
            if parts.next().is_some() {
                return Err(invalid_conda("malformed info/has_prefix path"));
            }
            if !relocated.insert(relative.to_owned()) {
                continue;
            }
            rewrite_prefix_file(
                &package_root.join(safe_relative(relative)?),
                prefix,
                object,
                mode == "binary",
            )?;
        }
    }
    rewrite_remaining_prefixes(package_root, placeholders, object)?;
    replace_pkg_config_wrapper(package_root)?;
    Ok(())
}

fn safe_relative(relative: &str) -> io::Result<PathBuf> {
    if relative.is_empty() || relative.contains('\\') {
        return Err(invalid_conda(format!("unsafe conda path {relative:?}")));
    }
    let path = Path::new(relative);
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(invalid_conda(format!("unsafe conda path {relative:?}")));
        }
    }
    Ok(path.to_path_buf())
}

pub fn rewrite_prefix_file(
    path: &Path,
    placeholder: &str,
    object: &Path,
    binary: bool,
) -> io::Result<()> {
    let target = object
        .to_str()
        .ok_or_else(|| invalid_conda("native object path is not UTF-8"))?;
    rewrite_prefix_file_with_target(path, placeholder, target, binary)
}

fn rewrite_prefix_file_with_target(
    path: &Path,
    placeholder: &str,
    target: &str,
    binary: bool,
) -> io::Result<()> {
    if placeholder.is_empty() {
        return Err(invalid_conda("empty conda prefix placeholder"));
    }
    let old = placeholder.as_bytes();
    let replacement = target.as_bytes();
    let mut bytes = fs::read(path)?;
    let changed = if binary {
        let mut changed = false;
        let mut string_start = 0;
        while string_start <= bytes.len() {
            let string_end = bytes[string_start..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|offset| string_start + offset)
                .unwrap_or(bytes.len());
            let string = bytes[string_start..string_end].to_vec();
            if find_bytes(&string, old).is_some() {
                let mut rewritten = Vec::with_capacity(string.len());
                let mut cursor = 0;
                while let Some(relative) = find_bytes(&string[cursor..], old) {
                    let start = cursor + relative;
                    rewritten.extend_from_slice(&string[cursor..start]);
                    rewritten.extend_from_slice(replacement);
                    cursor = start + old.len();
                }
                rewritten.extend_from_slice(&string[cursor..]);
                if rewritten.len() > string.len() {
                    return Err(invalid_conda(format!(
                        "rewritten native path {} is longer than original binary string in {} (placeholder {:?}, string length {}, replacement length {})",
                        target,
                        path.display(),
                        placeholder,
                        string.len(),
                        rewritten.len()
                    )));
                }
                rewritten.resize(string.len(), 0);
                bytes[string_start..string_end].copy_from_slice(&rewritten);
                changed = true;
            }
            if string_end == bytes.len() {
                break;
            }
            string_start = string_end + 1;
        }
        changed
    } else {
        let mut changed = false;
        let mut index = 0;
        while let Some(relative) = find_bytes(&bytes[index..], old) {
            let start = index + relative;
            bytes.splice(start..start + old.len(), replacement.iter().copied());
            index = start + replacement.len();
            changed = true;
        }
        changed
    };
    if !changed {
        return Err(invalid_conda(format!(
            "prefix placeholder is absent from {}",
            path.display()
        )));
    }
    fs::write(path, bytes)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut offset = 0;
    while let Some(relative) = haystack[offset..].iter().position(|byte| *byte == first) {
        let start = offset + relative;
        if haystack[start..].starts_with(needle) {
            return Some(start);
        }
        offset = start + 1;
        if offset >= haystack.len() {
            break;
        }
    }
    None
}

fn merge_tree(source: &Path, destination: &Path) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let source_type = fs::symlink_metadata(&from)?.file_type();
        if source_type.is_dir() {
            if to.exists() {
                if !fs::symlink_metadata(&to)?.is_dir() {
                    return Err(invalid_conda(format!(
                        "native package path collision at {}",
                        to.display()
                    )));
                }
            } else {
                fs::create_dir(&to)?;
            }
            merge_tree(&from, &to)?;
        } else {
            if fs::symlink_metadata(&to).is_ok() {
                return Err(invalid_conda(format!(
                    "native package path collision at {}",
                    to.display()
                )));
            }
            fs::rename(&from, &to)?;
        }
    }
    Ok(())
}

pub fn compose_env(object: &Path, base: &[(String, String)]) -> Vec<(String, String)> {
    let lib = object.join("lib").display().to_string();
    let include = object.join("include").display().to_string();
    let bin = object.join("bin").display().to_string();
    let mut out = base.to_vec();
    set_env(
        &mut out,
        "PKG_CONFIG_PATH",
        object.join("lib/pkgconfig").display().to_string(),
    );
    set_env(
        &mut out,
        "PKG_CONFIG_LIBDIR",
        object.join("lib/pkgconfig").display().to_string(),
    );
    append_env(&mut out, "CFLAGS", shell_quote_arg(&format!("-I{include}")));
    append_env(
        &mut out,
        "CXXFLAGS",
        shell_quote_arg(&format!("-I{include}")),
    );
    append_env(
        &mut out,
        "LDFLAGS",
        format!(
            "{} {}",
            shell_quote_arg(&format!("-L{lib}")),
            shell_quote_arg(&format!("-Wl,-rpath,{lib}")),
        ),
    );

    // cc-rs and other C build helpers read CFLAGS/LDFLAGS, but Cargo/rustc
    // deliberately do not. Supply the same native search path and runtime
    // rpath through both Rust flag channels Cargo understands. The encoded
    // form preserves each argument exactly, including paths containing spaces.
    let rust_args = [
        "-C".to_string(),
        format!("link-arg=-Wl,-rpath,{lib}"),
        "-L".to_string(),
        format!("native={lib}"),
    ];
    append_env(
        &mut out,
        "RUSTFLAGS",
        rust_args
            .iter()
            .map(|arg| shell_quote_arg(arg))
            .collect::<Vec<_>>()
            .join(" "),
    );
    append_encoded_env(&mut out, "CARGO_ENCODED_RUSTFLAGS", &rust_args);
    let path = out
        .iter()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.clone());
    set_env(
        &mut out,
        "PATH",
        match path {
            Some(path) if !path.is_empty() => prepend_after_first_path_entry(&path, &bin),
            _ => bin,
        },
    );
    out
}

fn prepend_after_first_path_entry(path: &str, entry: &str) -> String {
    let Some((first, rest)) = path.split_once(':') else {
        return format!("{path}:{entry}");
    };
    if rest.is_empty() {
        format!("{first}:{entry}")
    } else {
        format!("{first}:{entry}:{rest}")
    }
}

fn set_env(env: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some((_, current)) = env.iter_mut().find(|(name, _)| name == key) {
        *current = value;
    } else {
        env.push((key.into(), value));
    }
}

fn append_env(env: &mut Vec<(String, String)>, key: &str, suffix: String) {
    let value = env
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone());
    set_env(
        env,
        key,
        match value {
            Some(value) if !value.is_empty() => format!("{value} {suffix}"),
            _ => suffix,
        },
    );
}

/// Quote one compiler/linker argument for the shell-like flag parsers used by
/// setuptools, cc-rs, and Cargo's RUSTFLAGS handling. Paths without shell
/// metacharacters retain the historical compact form; paths containing a
/// space (or another special character) remain one complete argument.
fn shell_quote_arg(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/=,+@".contains(&byte))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Cargo separates CARGO_ENCODED_RUSTFLAGS arguments with ASCII unit
/// separator (0x1f). Unlike RUSTFLAGS, this channel does not need shell
/// quoting and therefore handles a store root containing spaces directly.
fn append_encoded_env(env: &mut Vec<(String, String)>, key: &str, args: &[String]) {
    let suffix = args.join("\x1f");
    let value = env
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone());
    set_env(
        env,
        key,
        match value {
            Some(value) if !value.is_empty() => format!("{value}\x1f{suffix}"),
            _ => suffix,
        },
    );
}

/// Read the native library object input recorded in a realized environment's
/// store metadata. Project closures use this to keep the libset live along
/// with the environment that contains extensions linked to it.
pub fn env_reference(env_object: &Path) -> io::Result<Option<serde_json::Value>> {
    let id = env_object
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "environment object has no id")
        })?;
    let store_root = env_object.parent().and_then(Path::parent).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "environment object has no store root",
        )
    })?;
    let metadata = store_root.join("meta").join(format!("{id}.json"));
    // An environment object with no recorded metadata cannot carry a
    // native_libs input (it predates the library set, or is a synthetic
    // object): that is "no reference", not a projection failure.
    let file = match File::open(&metadata) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let value: serde_json::Value = serde_json::from_reader(file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse {}: {e}", metadata.display()),
        )
    })?;
    let Some(native_id) = value["identity"]["inputs"]["native_libs"].as_str() else {
        return Ok(None);
    };
    if native_id.is_empty()
        || !native_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "environment native library id is malformed",
        ));
    }
    let path = store_root.join("objects").join(native_id);
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("native library object is missing: {}", path.display()),
        ));
    }
    Ok(Some(serde_json::json!({"id": native_id, "path": path})))
}

pub fn size_bytes(path: &Path) -> io::Result<u64> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(metadata.len());
    }
    let mut total = 0;
    for entry in fs::read_dir(path)? {
        total += size_bytes(&entry?.path())?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {

    /// The manifest hash is a digest over the pinned rows: each row's name,
    /// version, build, subdir, filename and archive sha256. It is pinned
    /// here as a literal, so dropping any field (notably the digests) from
    /// the producer's hash, or changing its format, fails this test.
    ///
    /// Changing a row of `LINUX_NATIVE_PACKAGES` changes this value too, on
    /// purpose: re-pinning the table moves every native-libs object id, so
    /// recompute the literal from the new table and paste it in.
    #[test]
    fn manifest_hash_covers_every_pinned_archive_digest() {
        assert_eq!(
            manifest_sha256(Platform::X86_64UnknownLinuxGnu).unwrap(),
            "3096767570d5ed24378a36e8d66bf700458004a8d9e635cd9a3a5a658b89b914",
            "the producer's manifest hash no longer covers the pinned rows"
        );
    }
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn temp_dir(label: &str) -> TempDir {
        TempDir::named(&format!("native-{label}"))
    }

    /// A conda `_path` that leaves the package root, or is spelled so a
    /// later join could, is refused; an ordinary relative path passes
    /// (#348).
    #[test]
    fn safe_relative_refuses_paths_that_leave_the_package() {
        for unsafe_path in [
            "",
            "../etc/passwd",
            "lib/../../escape",
            "/etc/passwd",
            "./lib/libz.so",
            "lib\\..\\escape",
        ] {
            let error = safe_relative(unsafe_path).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{unsafe_path:?}");
            assert!(
                error.to_string().contains("unsafe conda path"),
                "{unsafe_path:?}: {error}"
            );
        }
        assert_eq!(
            safe_relative("lib/pkgconfig/zlib.pc").unwrap(),
            Path::new("lib/pkgconfig/zlib.pc")
        );
    }

    /// Two packages that ship the same file, or a file where the other
    /// ships a directory, collide instead of one silently replacing the
    /// other; disjoint trees merge (#348).
    #[test]
    fn merge_tree_refuses_a_path_two_packages_both_ship() {
        let root = temp_dir("merge-tree");
        let (first, second, merged) = (
            root.0.join("first"),
            root.0.join("second"),
            root.0.join("merged"),
        );
        for dir in [&first, &second, &merged] {
            fs::create_dir_all(dir.join("lib")).unwrap();
        }
        fs::write(first.join("lib/libz.so.1"), "z").unwrap();
        fs::write(second.join("lib/libssl.so.3"), "ssl").unwrap();
        merge_tree(&first, &merged).unwrap();
        merge_tree(&second, &merged).unwrap();
        assert_eq!(fs::read(merged.join("lib/libz.so.1")).unwrap(), b"z");
        assert_eq!(fs::read(merged.join("lib/libssl.so.3")).unwrap(), b"ssl");

        let same = root.0.join("same");
        fs::create_dir_all(same.join("lib")).unwrap();
        fs::write(same.join("lib/libz.so.1"), "other z").unwrap();
        let error = merge_tree(&same, &merged).unwrap_err();
        assert!(error.to_string().contains("path collision"), "{error}");
        assert_eq!(fs::read(merged.join("lib/libz.so.1")).unwrap(), b"z");

        let file_over_dir = root.0.join("file-over-dir");
        fs::create_dir_all(&file_over_dir).unwrap();
        fs::write(file_over_dir.join("lib"), "not a dir").unwrap();
        let error = merge_tree(&file_over_dir, &merged).unwrap_err();
        assert!(error.to_string().contains("path collision"), "{error}");

        let dir_over_file = root.0.join("dir-over-file");
        fs::create_dir_all(dir_over_file.join("lib/libz.so.1")).unwrap();
        let error = merge_tree(&dir_over_file, &merged).unwrap_err();
        assert!(error.to_string().contains("path collision"), "{error}");
    }

    /// A placeholder left in any file after relocation refuses the set,
    /// naming the file; the generic conda-build placeholders refuse too,
    /// and a clean tree passes (#348).
    #[test]
    fn a_placeholder_that_survived_relocation_is_refused() {
        let root = temp_dir("placeholder-scan");
        fs::create_dir_all(root.0.join("lib/pkgconfig")).unwrap();
        fs::write(root.0.join("lib/pkgconfig/zlib.pc"), "prefix=/store/obj\n").unwrap();
        let placeholders = ["/opt/anaconda1anaconda2anaconda3".to_string()];
        scan_for_placeholders(&root.0, &placeholders).unwrap();

        fs::write(
            root.0.join("lib/pkgconfig/ssl.pc"),
            "prefix=/opt/anaconda1anaconda2anaconda3\n",
        )
        .unwrap();
        let error = scan_for_placeholders(&root.0, &placeholders).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("survived relocation"), "{error}");
        assert!(
            error.to_string().contains("lib/pkgconfig/ssl.pc"),
            "{error}"
        );
        fs::remove_file(root.0.join("lib/pkgconfig/ssl.pc")).unwrap();

        // Each generic marker refuses on its own, one file each.
        for (file, marker) in [
            ("lib/libfoo.so", "/home/build/_h_env_placehold/lib"),
            ("lib/libbar.so", "/opt/placehold_placehold/lib"),
        ] {
            let mut bytes = b"\x7fELF ".to_vec();
            bytes.extend_from_slice(marker.as_bytes());
            fs::write(root.0.join(file), bytes).unwrap();
            let error = scan_for_placeholders(&root.0, &placeholders).unwrap_err();
            assert!(error.to_string().contains(file), "{marker}: {error}");
            fs::remove_file(root.0.join(file)).unwrap();
        }
        scan_for_placeholders(&root.0, &placeholders).unwrap();
    }

    /// No package is pinned twice, and the object id names the store it
    /// lives in: the libraries' prefix is rewritten to the store path, so
    /// two stores never share one object.
    #[test]
    fn pin_table_names_are_unique_and_the_store_root_changes_the_id() {
        let mut names = std::collections::BTreeSet::new();
        for pin in LINUX_NATIVE_PACKAGES {
            assert!(
                names.insert(pin.name),
                "duplicate native package {}",
                pin.name
            );
        }
        let first = temp_dir("identity-first");
        let second = temp_dir("identity-second");
        let first_store = Store::for_test(first.0.clone());
        let second_store = Store::for_test(second.0.clone());
        assert_ne!(
            object_id_for(&first_store, Platform::X86_64UnknownLinuxGnu).unwrap(),
            object_id_for(&second_store, Platform::X86_64UnknownLinuxGnu).unwrap()
        );
    }

    #[test]
    fn rewrites_text_prefixes() {
        let root = temp_dir("text");
        let path = root.0.join("pango.pc");
        fs::write(
            &path,
            ["prefix=/old/prefix\nlibdir=$", "{prefix}/lib\n"].concat(),
        )
        .unwrap();
        rewrite_prefix_file(
            &path,
            "/old/prefix",
            Path::new("/store/objects/libset"),
            false,
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            ["prefix=/store/objects/libset\nlibdir=$", "{prefix}/lib\n"].concat()
        );
    }

    #[test]
    fn rewrites_binary_prefixes_with_null_padding() {
        let root = temp_dir("binary");
        let path = root.0.join("lib.so");
        fs::write(&path, b"head/old/prefix\0tail").unwrap();
        rewrite_prefix_file(&path, "/old/prefix", Path::new("/new"), true).unwrap();
        let bytes = fs::read(&path).unwrap();
        let mut expected = b"head/new".to_vec();
        expected.extend([0_u8; 8]);
        expected.extend(b"tail");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn binary_rewrite_preserves_the_complete_path_suffix() {
        let root = temp_dir("binary-suffix");
        let path = root.0.join("fontconfig.so");
        fs::write(
            &path,
            b"prefix=/old/prefix/etc/fonts/fonts.conf\0trailing-bytes",
        )
        .unwrap();
        rewrite_prefix_file(&path, "/old/prefix", Path::new("/new"), true).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            b"prefix=/new/etc/fonts/fonts.conf\0\0\0\0\0\0\0\0trailing-bytes"
        );
    }

    #[test]
    fn binary_rewrite_replaces_every_placeholder_in_every_string() {
        let root = temp_dir("binary-all");
        let path = root.0.join("fontconfig-cache");
        fs::write(
            &path,
            b"first=/old/prefix/a:/old/prefix/b\0second=/old/prefix/c\0tail",
        )
        .unwrap();
        rewrite_prefix_file(&path, "/old/prefix", Path::new("/new"), true).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes
            .windows(b"/old/prefix".len())
            .any(|window| window == b"/old/prefix"));
        assert!(
            bytes
                .windows(b"/new".len())
                .filter(|window| *window == b"/new")
                .count()
                >= 3
        );
        assert!(bytes.ends_with(b"tail"));
    }

    #[test]
    fn discovers_payload_embedded_placeholders_without_metadata() {
        let root = temp_dir("discover-placeholders");
        fs::write(
            root.0.join("payload"),
            b"/home/conda/feedstock_root/build_artifacts/pkg/_h_env_placehold_placehold_/lib\0placehold_placehold_placehold_/lib\0",
        )
        .unwrap();
        let placeholders = discover_payload_placeholders(&root.0).unwrap();
        assert!(placeholders.iter().any(|placeholder| {
            placeholder
                == "/home/conda/feedstock_root/build_artifacts/pkg/_h_env_placehold_placehold_"
        }));
        assert!(placeholders
            .iter()
            .any(|placeholder| placeholder == "placehold_placehold_placehold_"));
    }

    #[test]
    fn pkg_config_wrapper_does_not_replace_isolation_variables() {
        let root = temp_dir("pkg-config-wrapper");
        let bin = root.0.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(
            bin.join("pkg-config"),
            b"#!/usr/bin/env bash\nPKG_CONFIG_LIBDIR=/usr/lib/pkgconfig exec ./pkg-config.bin\n",
        )
        .unwrap();
        fs::write(bin.join("pkg-config.bin"), b"real binary").unwrap();
        replace_pkg_config_wrapper(&root.0).unwrap();
        let wrapper = fs::read_to_string(bin.join("pkg-config")).unwrap();
        assert_eq!(
            wrapper,
            "#!/bin/sh\nexec \"$(dirname \"$0\")/pkg-config.bin\" \"$@\"\n"
        );
        assert!(!wrapper.contains("/usr/lib/pkgconfig"));
    }

    #[test]
    fn binary_rewrite_refuses_a_longer_target() {
        let root = temp_dir("long");
        let path = root.0.join("lib.so");
        fs::write(&path, b"placeholder").unwrap();
        let error = rewrite_prefix_file(&path, "placeholder", Path::new("/a/path/longer"), true)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("longer than"));
    }

    #[test]
    fn native_env_composition_is_isolated_and_additive() {
        let env = compose_env(
            Path::new("/store/objects/libset"),
            &[
                (
                    "PATH".into(),
                    "/build-env/bin:/rust/bin:/usr/bin:/bin".into(),
                ),
                ("CFLAGS".into(), "-O2".into()),
            ],
        );
        let get = |key: &str| {
            env.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
                .unwrap()
        };
        assert_eq!(
            get("PKG_CONFIG_PATH"),
            "/store/objects/libset/lib/pkgconfig"
        );
        assert_eq!(
            get("PKG_CONFIG_LIBDIR"),
            "/store/objects/libset/lib/pkgconfig"
        );
        assert_eq!(get("CFLAGS"), "-O2 -I/store/objects/libset/include");
        assert_eq!(get("CXXFLAGS"), "-I/store/objects/libset/include");
        assert_eq!(
            get("LDFLAGS"),
            "-L/store/objects/libset/lib -Wl,-rpath,/store/objects/libset/lib"
        );
        assert_eq!(
            get("PATH"),
            "/build-env/bin:/store/objects/libset/bin:/rust/bin:/usr/bin:/bin"
        );
        assert_eq!(
            get("RUSTFLAGS"),
            "-C link-arg=-Wl,-rpath,/store/objects/libset/lib -L native=/store/objects/libset/lib"
        );
        assert_eq!(
            get("CARGO_ENCODED_RUSTFLAGS"),
            "-C\x1flink-arg=-Wl,-rpath,/store/objects/libset/lib\x1f-L\x1fnative=/store/objects/libset/lib"
        );
    }

    #[test]
    fn native_env_composition_quotes_store_paths_for_compilers() {
        let env = compose_env(
            Path::new("/store with spaces/objects/libset"),
            &[("PATH".into(), "/usr/bin:/bin".into())],
        );
        let get = |key: &str| {
            env.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
                .unwrap()
        };
        assert_eq!(
            get("PKG_CONFIG_PATH"),
            "/store with spaces/objects/libset/lib/pkgconfig"
        );
        assert_eq!(
            get("CFLAGS"),
            "'-I/store with spaces/objects/libset/include'"
        );
        assert_eq!(
            get("CXXFLAGS"),
            "'-I/store with spaces/objects/libset/include'"
        );
        assert_eq!(
            get("LDFLAGS"),
            "'-L/store with spaces/objects/libset/lib' '-Wl,-rpath,/store with spaces/objects/libset/lib'"
        );
        assert_eq!(
            get("RUSTFLAGS"),
            "-C 'link-arg=-Wl,-rpath,/store with spaces/objects/libset/lib' -L 'native=/store with spaces/objects/libset/lib'"
        );
        assert_eq!(
            get("CARGO_ENCODED_RUSTFLAGS"),
            "-C\x1flink-arg=-Wl,-rpath,/store with spaces/objects/libset/lib\x1f-L\x1fnative=/store with spaces/objects/libset/lib"
        );
    }
}
