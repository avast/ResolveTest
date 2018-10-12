// g++ --std=c++11 -o resolvetest resolvetest.cpp

#include <string>
#include <iostream>
#include <stdexcept>
#include <cassert>
#include <mutex>

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

std::string inet4str(const in_addr &in4) {
  char addr_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &in4, addr_str, sizeof(addr_str));
  return addr_str;
}

std::string inet6str(const in6_addr &in6){
  char addr_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &in6, addr_str, sizeof(addr_str));
  return addr_str;
}

bool resolve(int af, const std::string &resolveName){
  struct addrinfo hints = {};
  hints.ai_family = af;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;

  struct addrinfo* res0 = nullptr;
  int error = getaddrinfo(resolveName.c_str(), nullptr, &hints, &res0);
  if (error != 0) {
    std::cerr << "getaddrinfo fails " << gai_strerror(error) << std::endl;
    return false;
  }


  for (auto* res = res0; res; res = res->ai_next) {
    const struct sockaddr *sa = res->ai_addr;
    if (sa->sa_family == AF_INET){
      std::cout << "IPv4 " << inet4str(((const struct sockaddr_in *)sa)->sin_addr);
    } else if (sa->sa_family == AF_INET6){
      std::cout << "IPv6 " << inet6str(((const struct sockaddr_in6 *)sa)->sin6_addr);
    } else {
      std::cout << "INET(" << sa->sa_family << ") ";
    }

    std::cout << std::endl;
  }
  freeaddrinfo(res0);

  return true;
}

int main(int argc, const char* args[]){
  // Libresolv does not work with uClibc 0.9.32 due to bug, see:
  // http://lists.busybox.net/pipermail/uclibc-cvs/2012-July/030778.html
  // We query A, the first response is CNAME, this causes unparsable output from the library.

  std::string resolveName;
  if (argc > 1){
    resolveName = args[1];
  } else {
    resolveName = "ncc.avast.com";
  }
  std::cout << "Resolving " << resolveName << std::endl;

  if (resolve(AF_INET, resolveName) && resolve(AF_INET6, resolveName)) {
    std::cout << "OK" << std::endl;
    return 0;
  }else{
    std::cout << "FAILURE" << std::endl;
    return 1;
  }
}
