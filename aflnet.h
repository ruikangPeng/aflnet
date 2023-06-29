#ifndef __AFLNET_H
#define __AFLNET_H 1

#include "klist.h"
#include "khash.h"
#include <arpa/inet.h>
#include <poll.h>

typedef struct {
  int start_byte;                 /* 起始字节，如果未知则为负数         */
  int end_byte;                   /* 最后一个字节，如果未知则为负数      */
  char modifiable;                /* 可修改的标志                      */
  unsigned int *state_sequence;   /* 保存状态反馈的注解(The annotation keeping the state feedback) */
  unsigned int state_count;       /* 存储在 state_sequence 中的状态数量 */
} region_t;   //状态链的数据结构

typedef struct {
  char *mdata; /* 保存消息数据的缓冲区 */
  int msize;   /* 消息大小            */
} message_t;

typedef struct {
  u32 id;                     /* 状态 id                                                   */
  u8 is_covered;              /* 这个状态是否已被覆盖                                        */
  u32 paths;                  /* 执行这个状态的路径总数                                      */
  u32 paths_discovered;       /* 当选择目标状态时，发现的新路径总数                           */
  u32 selected_times;         /* 选择该状态的总次数                                          */
  u32 fuzzs;                  /* 模糊测试的总次数（即生成的输入数量）                          */
  u32 score;                  /* 当前状态的评分                                              */
  u32 selected_seed_index;    /* 最近选择的种子索引                                          */
  void **seeds;               /* 保存到达该状态的所有种子(可以转换为 struct queue_entry* 类型) */
  u32 seeds_count;            /* 种子的总数，它必须等于种子数组的大小                          */
} state_info_t;

enum {
  /* 00 */ PRO_TCP,
  /* 01 */ PRO_UDP
};

enum {
  /* 00 */ INVALID_SELECTION,
  /* 01 */ RANDOM_SELECTION,
  /* 02 */ ROUND_ROBIN,
  /* 03 */ FAVOR
};

// Initialize klist linked list data structure
#define message_t_freer(x)
KLIST_INIT(lms, message_t *, message_t_freer)

KHASH_SET_INIT_INT(hs32)

// Initialize a hash table with int key and value is of type state_info_t
KHASH_INIT(hms, khint32_t, state_info_t *, 1, kh_int_hash_func, kh_int_hash_equal)

// Functions for extracting requests and responses

/*To add support for a new application protocol, please add corresponding function declartion and implementation
And update the code to handle -P option in the main function in afl-fuzz.c accordingly */

unsigned int* extract_response_codes_smtp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_ssh(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_tls(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_dicom(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_dns(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_ftp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_rtsp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_dtls12(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_sip(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_http(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_ipp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
extern unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);

region_t* extract_requests_smtp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_ssh(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_tls(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_dicom(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_dns(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_ftp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_rtsp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_dtls12(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_sip(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_http(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_ipp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
extern region_t* (*extract_requests)(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);

// Network communication functions

// 发送和接收数据的两个包装器（或者说封装函数）
int net_send(int sockfd, struct timeval timeout, char *mem, unsigned int len);
int net_recv(int sockfd, struct timeval timeout, int poll_w, char **response_buf, unsigned int *len);

// kl_messages manipulating functions

/* Construct a new linked list to store all messages from a list of regions */
klist_t(lms) *construct_kl_messages(u8* fname, region_t *regions, u32 region_count);

/* Free all items and delete kl_messages */
void delete_kl_messages(klist_t(lms) *kl_messages);

/* Get the last message in the linked list. As kl_messages->tail points to an empty item, we cannot use it to get the last message */
kliter_t(lms) *get_last_message(klist_t(lms) *kl_messages);

/* Save a list of messages to a file. If replay_enabled is set, the file will be structured for replaying. Otherwise, just save the raw data */
u32 save_kl_messages_to_file(klist_t(lms) *kl_messages, u8 *fname, u8 replay_enabled, u32 max_count);

/* Convert back a linked list of messages to regions to maintain the message sequence structure as much as possible */
region_t* convert_kl_messages_to_regions(klist_t(lms) *kl_messages, u32* region_count_ref, u32 max_count);

// Utility functions

/* Save regions' information to file for debugging purpose */
void save_regions_to_file(region_t *regions, unsigned int region_count, unsigned char *fname);

/* Split a string using a delimiter */
int str_split(char* a_str, const char* a_delim, char **result, int a_count);

/* Remove unwanted characters from the right */
void str_rtrim(char* a_str);

/* Parse user provided server information to get IP address, transport protocol (TCP/UDP) and port number */
int parse_net_config(u8* net_config, u8* protocol, u8** ip_address, u32* port);

/* Convert state sequence to string */
u8* state_sequence_to_string(unsigned int *stateSequence, unsigned int stateCount);

/* Print the hexdump of a segment of a buffer preceded by a messsage */
void hexdump(unsigned char *msg, unsigned char * buf, int start, int end);

/* Reads a number of bytes from buf from offset into an unsigned int and returns it. May overflow*/
u32 read_bytes_to_uint32(unsigned char* buf, unsigned int offset, int num_bytes);

#endif /* __AFLNET_H */
