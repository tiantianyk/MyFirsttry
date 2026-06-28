#include "wm_decode.h"

int wm_decode(const uint8_t *data, size_t len, wm_packet_t *out)
{
    if (len < WM_HEADER_LEN || data == NULL || out == NULL) {
        return -1;
    }

    uint64_t header = (uint64_t)data[0] << 32 | (uint64_t)data[1] << 24 |
                      (uint64_t)data[2] << 16 | (uint64_t)data[3] << 8  |
                      (uint64_t)data[4];

    out->next_hop_id = (header >> 33) & 0x7F;
    out->prev_hop_id = (header >> 26) & 0x7F;
    out->msg_type = (header >> 22) & 0x0F;
    out->msg_subtype = (header >> 18) & 0x0F;
    out->trans_mode = (header >> 17) & 0x01;
    out->qos_priority = (header >> 14) & 0x07;
    out->ttl = (header >> 8) & 0x3F;
    out->src_node_id = (header >> 1) & 0x7F;
    out->reserved = header & 0x01;

    return 0;
}