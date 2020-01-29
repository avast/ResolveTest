// g++ --std=c++11 -o resolvetest resolvetest.cpp -lresolv

#include <string>
#include <iostream>
#include <stdexcept>
#include <cassert>
#include <mutex>
#include <vector>
#include <cstring>

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

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

#define RESOLV_STATE (_res)

bool parse_record(ns_msg &msg, const int rrnum){
  ns_rr rr;
  if (ns_parserr(&msg, ns_s_an, rrnum, &rr) < 0)
  {
    std::cerr << "ns_parserr" << std::endl;
    return false;
  }
  int rdlen = ns_rr_rdlen(rr);

  std::cout << ns_rr_name(rr) << " ";

  // Decode data field (not done by ns_parserr)
  switch (ns_rr_type(rr))
  {
    case ns_t_a:
      // IPv4 address
      std::cout << "A: " << inet4str(*((in_addr *)ns_rr_rdata(rr)));
      break;
    case ns_t_aaaa:
      // IPv6 address
      std::cout << "AAA: " << inet4str(*((in_addr *)ns_rr_rdata(rr)));
      break;
    case ns_t_txt:
    {
      // <character-string>: length (1 octet), string
      if (rdlen < 1) {
        std::cerr << "Invalid TXT record (no data)";
        return false;
      }
      size_t length = *ns_rr_rdata(rr);
      if (rdlen < 1 + (int)length) {
        std::cerr << "Invalid TXT record";
        return false;
      }
      std::cout << "TXT: " << std::string((const char *)(ns_rr_rdata(rr) + 1), length);
      break;
    }
    case ns_t_ns:
    case ns_t_cname:
    {
      // <domain-name> (compressed)
      char nsname[NS_MAXDNAME];
      if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
                             ns_rr_rdata(rr), nsname, NS_MAXDNAME) < 0)
      {
        std::cerr << "ns_name_uncompress failed" << std::endl;
        return false;
      }
      std::cout << "CNAME: " << nsname;
      break;
    }
    case ns_t_mx:
    {
      // MX: preference (2 octets), <domain-name> (compressed)
      char nsname[NS_MAXDNAME];
      uint16_t preference = ntohs(*(uint16_t *) ns_rr_rdata(rr));
      if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
                             ns_rr_rdata(rr) + 2, nsname, NS_MAXDNAME) < 0)
      {
        std::cerr << "ns_name_uncompress failed" << std::endl;
        return false;
      }
      std::cout << "MX: " << nsname;
      std::cout << "(mx_preference = " << preference << ")";
      break;
    }
    case ns_t_soa:
      assert(!"Dns: SOA parsing - not implemented");
      break;
    case ns_t_srv:
      assert(!"Dns: SRV parsing - not implemented");
      break;
    default:
      // Other fields: no data copied
      std::cout << "TYPE " << ns_rr_type(rr);
      break;
  }

  std::cout << std::endl << "  ";
  std::cout << "TTL " << ns_rr_ttl(rr) << " ";
  std::cout << "CLASS " << ns_rr_class(rr) << " ";
  std::cout << std::endl;

  return true;
}


bool query(int type, const std::string &resolveName, int cls = ns_c_in){

  std::vector<u_char> ansbuf(1024, 0);

  for (;;) {
    // Repeat the query until our buffer is large enough for the response
    int anslen = res_query(resolveName.c_str(), cls, type, ansbuf.data(), (int) ansbuf.size());
    if (anslen == -1) {
      if (RESOLV_STATE.res_h_errno == NO_DATA) {
        // Valid name, no data record of requested type
        // This is success, but we don't yield any record
        std::cout << "no data" << std::endl;
        return true;
      }
      std::cerr << "res_query(" << resolveName << ", " << type << "): " << hstrerror(RESOLV_STATE.res_h_errno) << std::endl;
      return false;
    }
    // Was our buffer large enough?
    if (anslen > (int)ansbuf.size()) {
      // Grow to requested size
      ansbuf.resize((size_t) anslen);
    } else {
      // Shrink to actual size of the response
      ansbuf.resize((size_t) anslen);
      break;
    }
  }

  ns_msg msg;
  int rc = ns_initparse(ansbuf.data(), (int) ansbuf.size(), &msg);
  if (rc == -1) {
    std::cerr << "ns_initparse(): " << hstrerror(RESOLV_STATE.res_h_errno) << std::endl;
    return false;  // Could not parse
  }

  rc = ns_msg_getflag(msg, ns_f_rcode);
  if (rc != ns_r_noerror) {
    // We will never get here, because errors are handled by res_nquery.
    // If we did (by sending query in another way), we'd get finer grained
    // error codes as defined in nameser.h - ns_r_*
    std::cerr << "query error: " << rc << std::endl;
    return false;
  }

  for (int rrnum = 0; rrnum < ns_msg_count(msg, ns_s_an); rrnum++)
  {
    if (!parse_record(msg, rrnum)) {
       std::cerr << "could not parse response";
       return false;
    }
  }

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

  std::cout << std::endl << "System resolve:" << std::endl;

  if (resolve(AF_INET, resolveName) && resolve(AF_INET6, resolveName)) {
    std::cout << "OK" << std::endl;
  }else{
    std::cerr << "FAILURE" << std::endl;
    return 1;
  }

  if (res_init() != 0){
    std::cerr << "res_init FAILURE" << std::endl;
    return 1;
  }

  std::cout << std::endl << "DNS query:" << std::endl;
  if (query(ns_t_a, resolveName) && query(ns_t_aaaa, resolveName)){
    std::cout << "OK" << std::endl;
  }else{
    std::cerr << "query FAILURE" << std::endl;
    return 1;
  }

  return 0;
}
