# Bouncycastle OCSP Signature verification reproducer

This repository contains a minimal example to reproduce a [(possible) issue](https://github.com/bcgit/bc-java/issues/2254) with Bouncycastle's OCSP 
signature verification. If a revocation checker is used which already has an OCSP response for 
the end entity certificate provided, Bouncycastle seems to ignore the verification status of the 
signature of the OCSP response.

The issue is demonstrated by `OcspTest.java`. To run:

```bash
mvn clean test
```
