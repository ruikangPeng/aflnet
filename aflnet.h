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
} region_t;   

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

// 初始化 klist 链表数据结构
#define message_t_freer(x)
KLIST_INIT(lms, message_t *, message_t_freer)

KHASH_SET_INIT_INT(hs32)

// 初始化一个具有 int 键和值类型为 state_info_t 的哈希表
KHASH_INIT(hms, khint32_t, state_info_t *, 1, kh_int_hash_func, kh_int_hash_equal)

// 提取请求和响应的函数

/*  要为新的应用协议添加支持，请添加相应的函数声明和实现。
    并相应地更新 afl-fuzz.c 主函数的代码以处理 -P 选项 */

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

// 网络通信函数

// 发送和接收数据的两个包装器（或者说封装函数）
int net_send(int sockfd, struct timeval timeout, char *mem, unsigned int len);
int net_recv(int sockfd, struct timeval timeout, int poll_w, char **response_buf, unsigned int *len);

// kl_messages 操作函数

/* 构建一个新的链表，用于存储来自一组 region 的所有消息。 */
klist_t(lms) *construct_kl_messages(u8* fname, region_t *regions, u32 region_count);

/* 释放所有items并删除 kl_messages。 */
void delete_kl_messages(klist_t(lms) *kl_messages);

/* 获取链表中的最后一条消息。由于 kl_messages->tail 指向一个空项，因此我们不能使用它来获取最后一条消息。 */
kliter_t(lms) *get_last_message(klist_t(lms) *kl_messages);

/* 将消息列表保存到文件中。如果 replay_enabled 被设置，文件将以重放的方式结构化。否则，只保存原始数据。 */
u32 save_kl_messages_to_file(klist_t(lms) *kl_messages, u8 *fname, u8 replay_enabled, u32 max_count);

/* 将消息的链表转换regions，以尽可能地保持消息序列的结构。 */
region_t* convert_kl_messages_to_regions(klist_t(lms) *kl_messages, u32* region_count_ref, u32 max_count);

// Utility functions

/* 将 region 的信息保存到文件中，用于调试 */
void save_regions_to_file(region_t *regions, unsigned int region_count, unsigned char *fname);

/* 使用分隔符拆分一个字符串 */
int str_split(char* a_str, const char* a_delim, char **result, int a_count);

/* 从右侧删除不需要的字符。 */
void str_rtrim(char* a_str);

/* 解析用户提供的服务器信息，以获取 IP 地址、传输协议（TCP/UDP）和端口号。 */
int parse_net_config(u8* net_config, u8* protocol, u8** ip_address, u32* port);

/* 将状态序列转换为字符串。 */
u8* state_sequence_to_string(unsigned int *stateSequence, unsigned int stateCount);

/* 打印缓冲区片段的 hexdump，前面带有一条消息。 */
void hexdump(unsigned char *msg, unsigned char * buf, int start, int end);

/* 从缓冲区 buf 的偏移量开始读取指定数量的字节，并将其转换为无符号整数并返回。可能会溢出 */
u32 read_bytes_to_uint32(unsigned char* buf, unsigned int offset, int num_bytes);

#endif /* __AFLNET_H */
