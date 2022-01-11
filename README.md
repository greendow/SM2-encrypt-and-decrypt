# SM2-encrypt-and-decrypt
&ensp;&ensp;&ensp;&ensp;An implementation of computing SM2 encryption and decryption is provided. Header files and library files of OpenSSL 1.1.1 are needed while compiling and linking. OpenSSL website is: https://www.openssl.org
  
&ensp;&ensp;&ensp;&ensp;SM2 is a cryptographic algorithm based on elliptic curves. It is defined in the following standards of China:
- GB/T32918.1-2016,
- GB/T32918.2-2016,
- GB/T32918.3-2016,
- GB/T32918.4-2016,
- GM/T 0003-2012.  
  
&ensp;&ensp;&ensp;&ensp;Computing SM2 encryption and decryption are supported in OpenSSL 1.1.1. In the source package, "/crypto/sm2/sm2_crypt.c" is a good example. SM2 Encryption and decryption are encapsulated in an abstract level called EVP. In some cases using EVP interfaces to compute SM2 encryption and decryption is a little inconvenient. An implementation bypassing invoking OpenSSL EVP interfaces directly is given here.


Work with OpenSSL 3.0.0 ?  
&ensp;&ensp;&ensp;&ensp;The codes here is designed to be run with OpenSSL 1.1.1. If the codes are compiled with OpenSSL 3.0.0 on Linux platform, many warnings are shown. But it can be run with OpenSSL 3.0.0. Test with CentOS Linux 7.9 + gcc 4.8.5 + OpenSSL 3.0.0 has passed. The codes cannot be compiled on Windows platform with OpenSSL 3.0.0.
