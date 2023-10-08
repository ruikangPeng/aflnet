#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "alloc-inl.h"
#include "aflnet.h"

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;


/**
 * 函数功能：读取文件 packet_file 到 fsize 大小的 buf 中，并返回指向 buf 的指针。
*/
char *get_test_case(char* packet_file, int *fsize)
{
  /* open packet file */
  s32 fd = open(packet_file, O_RDONLY);

  *fsize = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  /* allocate buffer to read the file */
  char *buf = ck_alloc(*fsize);
  ck_read(fd, buf, *fsize, "packet file");

  return buf;
}

/* 参数:
1. 测试用例的路径（例如，引发崩溃的输入）
2. 应用层协议（例如，RTSP，FTP）
3. 服务器的网络端口
可选参数:
4. 首次响应超时（毫秒），默认值为1
5. 后续响应超时（微秒），默认值为1000
*/

int main(int argc, char* argv[])
{
  int portno, n;
  struct sockaddr_in serv_addr;
  char* buf = NULL, *response_buf = NULL;
  int buf_size = 0;
  int response_buf_size = 0;
  unsigned int i, state_count;
  unsigned int *state_sequence;
  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;

  if (argc < 4) {
    PFATAL("Usage: ./afl-replay packet_file protocol port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]");
  }

  if (!strcmp(argv[2], "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
  else if (!strcmp(argv[2], "FTP")) extract_response_codes = &extract_response_codes_ftp;
  else if (!strcmp(argv[2], "DNS")) extract_response_codes = &extract_response_codes_dns;
  else if (!strcmp(argv[2], "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
  else if (!strcmp(argv[2], "DICOM")) extract_response_codes = &extract_response_codes_dicom;
  else if (!strcmp(argv[2], "SMTP")) extract_response_codes = &extract_response_codes_smtp;
  else if (!strcmp(argv[2], "SSH")) extract_response_codes = &extract_response_codes_ssh;
  else if (!strcmp(argv[2], "TLS")) extract_response_codes = &extract_response_codes_tls;
  else if (!strcmp(argv[2], "SIP")) extract_response_codes = &extract_response_codes_sip;
  else if (!strcmp(argv[2], "HTTP")) extract_response_codes = &extract_response_codes_http;
  else if (!strcmp(argv[2], "IPP")) extract_response_codes = &extract_response_codes_ipp;
  else {fprintf(stderr, "[AFL-replay] Protocol %s has not been supported yet!\n", argv[2]); exit(1);}

  portno = atoi(argv[3]);

  if (argc > 4) {
    poll_timeout = atoi(argv[4]);
    if (argc > 5) {
      socket_timeout = atoi(argv[5]);
    }
  }

  //等待服务器初始化
  usleep(server_wait_usecs);

  int sockfd;
  if ((!strcmp(argv[2], "DTLS12")) || (!strcmp(argv[2], "DNS")) || (!strcmp(argv[2], "SIP"))) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  } else {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  //为套接字数据的发送/接收设置超时时间，否则会导致较大的延迟。
  //如果服务器在处理完所有请求后仍然存活。
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  /**
   * 指定的套接字 sockfd 上设置发送数据的超时选项，超时的值由 timeout 变量表示。
   * 这可以用来控制在发送数据时，如果数据发送花费的时间超过了 timeout 中指定的时间，套接字操作将会超时并返回，以防止发送操作无限阻塞。
   * 这对于确保网络通信操作不会无限期地阻塞程序很有用，特别是在处理套接字通信时。
  */
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    //如果无法连接到待测试的服务器
    //由于服务器初始启动时间不固定，再次尝试
    for (n=0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
      usleep(1000);
    }
    if (n== 1000) {
      close(sockfd);
      return 1;
    }
  }

  buf = get_test_case(argv[1], &buf_size);
  
  //将 request 存储在生成的种子输入中
  n = net_send(sockfd, timeout, buf, buf_size);

  //收到服务端的响应
  net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size);

  close(sockfd);

  //提取响应码
  state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  fprintf(stderr,"\n--------------------------------");
  fprintf(stderr,"\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr,"%d-",state_sequence[i]);
  }

  fprintf(stderr,"\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
  for (i=0; i < response_buf_size; i++) {
    fprintf(stderr,"%c",response_buf[i]);
  }
  fprintf(stderr,"\n--------------------------------");

  //Free memory
  ck_free(state_sequence);
  if (buf) ck_free(buf);
  ck_free(response_buf);

  return 0;
}

