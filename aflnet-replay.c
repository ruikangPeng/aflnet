#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "alloc-inl.h"
#include "aflnet.h"

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;

/* 预期参数：
  1.测试用例的路径（例如，碰撞触发输入）
  2.应用程序协议（如RTSP、FTP）
  3.服务器的网络端口
可选：
  4.首次响应超时（ms），默认为1
  5.后续响应超时（us），默认为1000
*/

int main(int argc, char* argv[])
{
  FILE *fp;
  int portno, n;
  struct sockaddr_in serv_addr;
  char* buf = NULL, *response_buf = NULL;
  int response_buf_size = 0;
  unsigned int size, i, state_count, packet_count = 0;
  unsigned int *state_sequence;
  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;


  if (argc < 4) {
    PFATAL("Usage: ./aflnet-replay packet_file protocol port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]");
  }

  fp = fopen(argv[1],"rb");

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
  else {fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[2]); exit(1);}

  portno = atoi(argv[3]);

  if (argc > 4) {
    poll_timeout = atoi(argv[4]);
    if (argc > 5) {
      socket_timeout = atoi(argv[5]);
    }
  }

  //等待服务器初始化
  usleep(server_wait_usecs);

  if (response_buf) {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  int sockfd;
  if ((!strcmp(argv[2], "DTLS12")) || (!strcmp(argv[2], "DNS")) || (!strcmp(argv[2], "SIP"))) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  } else {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  //设置套接字数据发送/接收的超时---否则会导致大的延迟
  //如果服务器在处理完所有请求后仍处于活动状态
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    //如果无法连接到测试中的服务器
    //请在服务器初始启动时间不同时重试
    for (n=0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
      usleep(1000);
    }
    if (n== 1000) {
      close(sockfd);
      return 1;
    }
  }

  //逐个发送请求
  //并保存所有服务器响应
  while(!feof(fp)) {
    if (buf) {ck_free(buf); buf = NULL;}
    if (fread(&size, sizeof(unsigned int), 1, fp) > 0) {
      packet_count++;
    	fprintf(stderr,"\nSize of the current packet %d is  %d\n", packet_count, size);

      buf = (char *)ck_alloc(size);
      fread(buf, size, 1, fp);

      if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
      n = net_send(sockfd, timeout, buf,size);
      if (n != size) break;

      if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
    }
  }

  fclose(fp);
  close(sockfd);

  //提取响应代码
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
  fprintf(stderr,"\n--------------------------------\n");

  //Free memory
  ck_free(state_sequence);
  if (buf) ck_free(buf);
  ck_free(response_buf);

  return 0;
}

