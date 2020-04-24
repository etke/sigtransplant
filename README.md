# sigtransplant

[![crates.io](https://img.shields.io/crates/v/sigtransplant.svg)](https://crates.io/crates/sigtransplant) [![github-actions](https://github.com/etke/sigtransplant/workflows/github%20actions/badge.svg?branch=master)](https://github.com/etke/sigtransplant/actions)

Transplant a valid code signature from one Portable Executable (PE) binary to another unsigned one.

This is a simple utility to test implementations that may only validate the existence of a valid code certificate signature but not the validity pertaining to the binary it is appended to.

## Install

```sh
cargo install sigtransplant
```

## Build/Install

```sh
git clone https://github.com/etke/sigtransplant
cd sigtransplant
cargo build --release
cargo install --path .
```

## Usage

```sh
Usage: sigtransplant <signed input> <unsigned input> <output>
```

### Example

```sh
sigtransplant C:\\Windows\\System32\\ntdll.dll target.exe modified.exe
writing modified PE binary...
wrote 674304 bytes to modified.exe
appending certificate table...
wrote 26200 bytes to modified.exe
```

```powershell
Get-AuthenticodeSignature -FilePath .\modified.exe


    Directory: C:\Users\etke\


SignerCertificate                         Status                                 Path
-----------------                         ------                                 ----
2FCC77934AAC546397EEE37C391229C9031DD785  HashMismatch                           modified.exe

```

```powershell
signtool.exe verify /v .\modified.exe

Verifying: .\modified.exe

Signature Index: 0 (Primary Signature)
Hash of file (sha256): 9CDAE679AFDE1E14DAB23F5CA5FF818AF502F7C2D2CD5F17945C810363EEA4D0

Signing Certificate Chain:
    Issued to: Microsoft Root Certificate Authority 2010
    Issued by: Microsoft Root Certificate Authority 2010
    Expires:   Sat Jun 23 15:04:01 2035
    SHA1 hash: 3B1EFD3A66EA28B16697394703A72CA340A05BD5

        Issued to: Microsoft Windows Production PCA 2011
        Issued by: Microsoft Root Certificate Authority 2010
        Expires:   Mon Oct 19 11:51:42 2026
        SHA1 hash: 580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D

            Issued to: Microsoft Windows
            Issued by: Microsoft Windows Production PCA 2011
            Expires:   Fri Jan 22 12:26:53 2021
            SHA1 hash: 2FCC77934AAC546397EEE37C391229C9031DD785

The signature is timestamped: Wed Apr 08 18:10:08 2020
Timestamp Verified by:
    Issued to: Microsoft Root Certificate Authority 2010
    Issued by: Microsoft Root Certificate Authority 2010
    Expires:   Sat Jun 23 15:04:01 2035
    SHA1 hash: 3B1EFD3A66EA28B16697394703A72CA340A05BD5

        Issued to: Microsoft Time-Stamp PCA 2010
        Issued by: Microsoft Root Certificate Authority 2010
        Expires:   Tue Jul 01 14:46:55 2025
        SHA1 hash: 2AA752FE64C49ABE82913C463529CF10FF2F04EE

            Issued to: Microsoft Time-Stamp Service
            Issued by: Microsoft Time-Stamp PCA 2010
            Expires:   Thu Feb 11 14:40:43 2021
            SHA1 hash: 50EC03FC971BA4A54C5E9176561EFB33254D9BD9

SignTool Error: WinVerifyTrust returned error: 0x80096010
        The digital signature of the object did not verify.

Number of files successfully Verified: 0
Number of warnings: 0
Number of errors: 1
```

## References

* **Authenticode verification vulnerability pattern**
    [https://blog.devsecurity.eu/en/blog/Authenticode-verification-vulnerability-pattern-CreateFromSignedFile](https://blog.devsecurity.eu/en/blog/Authenticode-verification-vulnerability-pattern-CreateFromSignedFile)

* **Application of Authenticode Signatures to Unsigned Code**
    [http://www.exploit-monday.com/2017/08/application-of-authenticode-signatures.html](http://www.exploit-monday.com/2017/08/application-of-authenticode-signatures.html)

* **SigPirate**
    [https://github.com/xorrior/Random-CSharpTools/tree/master/SigPirate/SigPirate](https://github.com/xorrior/Random-CSharpTools/tree/master/SigPirate/SigPirate)

* **SigThief**
    [https://github.com/secretsquirrel/SigThief](https://github.com/secretsquirrel/SigThief)
