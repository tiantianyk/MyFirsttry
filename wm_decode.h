#ifndef WM_DECODE_H
#define WM_DECODE_H

#include <stdint.h>
#include <stddef.h>

#define WM_HEADER_LEN 5

#define WM_MSG_TYPE_INTERNAL   0x0
#define WM_MSG_TYPE_FREQUENCY  0x1

#define WM_SUBTYPE_HELLO       0x0
#define WM_SUBTYPE_TC          0x1
#define WM_SUBTYPE_HNA         0x2
#define WM_SUBTYPE_SYNC        0x1

#define WM_SUBTYPE_CMD         0x0
#define WM_SUBTYPE_DATA        0x1

#define WM_TRANS_MODE_UNICAST  0
#define WM_TRANS_MODE_BROADCAST 1

#define WM_NODE_ID_INVALID     0
#define WM_NODE_ID_BROADCAST   65

typedef struct {
    uint8_t next_hop_id;
    uint8_t prev_hop_id;
    uint8_t msg_type;
    uint8_t msg_subtype;
    uint8_t trans_mode;
    uint8_t qos_priority;
    uint8_t ttl;
    uint8_t src_node_id;
    uint8_t reserved;
} wm_packet_t;

int wm_decode(const uint8_t *data, size_t len, wm_packet_t *out);

#endif