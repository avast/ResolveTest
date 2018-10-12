# ResolveTest

Simple dns resolve utility.

possible output:
```bash
$ ./cmake-build-debug/resolvetest 
Resolving ncc.avast.com

System resolve:
IPv4 2.21.74.51
IPv4 2.21.74.56
IPv6 2a02:26f0:132::215:4a08
IPv6 2a02:26f0:132::215:4a19
OK

DNS query:
ncc.avast.com CNAME: ncc.avast.com.edgesuite.net
  TTL 2868 CLASS 1 
ncc.avast.com.edgesuite.net CNAME: a1488.dscd.akamai.net
  TTL 2773 CLASS 1 
ncc.avast.com CNAME: ncc.avast.com.edgesuite.net
  TTL 2868 CLASS 1 
ncc.avast.com.edgesuite.net CNAME: a1488.dscd.akamai.net
  TTL 2773 CLASS 1 
OK
```

...this utility was created as a test for old, buggy versions of uClibc.
