#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

struct UserInfo{
  uint32_t socket;
  string username;
  uint32_t nonce;
  sockaddr_in address;
};
/*
struct ChallengeRequest{
     char username[25];
     char nonce;
};*/
