#ifndef ARP_DECODE_H
#define ARP_DECODE_H

#include <stdint.h>
#include <stddef.h>

/* ARP 硬件类型（常见值） */
#define ARP_HRD_ETHERNET    1

/* ARP 协议类型（常见值） */
#define ARP_PROT_IPV4       0x0800
#define ARP_PROT_IPV6       0x86DD

/* ARP Opcode */
#define ARP_OP_REQUEST      1
#define ARP_OP_REPLY        2
#define ARP_OP_RREQUEST     3
#define ARP_OP_RREPLY       4

/* 最大支持地址长度（bytes），用于栈上数组 */
#define ARP_MAX_ADDR_LEN    16   /* IPv6 是 16 字节，够用 */

/* 解析结果结构体 */
typedef struct {
    uint16_t hw_type;                  /* 硬件类型 */
    uint16_t proto_type;               /* 协议类型 */
    uint8_t  hw_len;                   /* 硬件地址长度（bytes） */
    uint8_t  proto_len;                /* 协议地址长度（bytes） */
    uint16_t opcode;                   /* 操作码 */

    uint8_t  sender_hw[ARP_MAX_ADDR_LEN];  /* 发送方硬件地址 */
    uint8_t  sender_proto[ARP_MAX_ADDR_LEN]; /* 发送方协议地址 */
    uint8_t  target_hw[ARP_MAX_ADDR_LEN];  /* 目标硬件地址 */
    uint8_t  target_proto[ARP_MAX_ADDR_LEN]; /* 目标协议地址 */

    /* 地址实际有效长度，方便调用方读取 */
    size_t   sender_hw_len;
    size_t   sender_proto_len;
    size_t   target_hw_len;
    size_t   target_proto_len;
} arp_packet_t;

/*
 * arp_decode - 从原始字节流解析 ARP 报文
 *
 * @data: 指向 ARP 头部起始字节的指针（不含以太网帧头）
 * @len:  data 区域的长度
 * @out:  输出结构体
 *
 * 返回值: 0  成功
 *        -1  数据不足（无法解析固定头部或地址字段不完整）
 *        -2  地址长度超出 ARP_MAX_ADDR_LEN
 */
int arp_decode(const uint8_t *data, size_t len, arp_packet_t *out);

#endif /* ARP_DECODE_H */
