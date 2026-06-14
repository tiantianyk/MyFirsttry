#include "arp_decode.h"

int arp_decode(const uint8_t *data, size_t len, arp_packet_t *out)
{
    size_t offset = 0;

    if (!data || !out)
        return -1;

    /* ---- 固定头部：8 bytes ---- */
    if (len < 8)
        return -1;

    out->hw_type    = (uint16_t)(data[0] << 8) | data[1];
    out->proto_type = (uint16_t)(data[2] << 8) | data[3];
    out->hw_len     = data[4];
    out->proto_len  = data[5];
    out->opcode     = (uint16_t)(data[6] << 8) | data[7];
    offset = 8;

    /* ---- 检查地址长度是否超出缓存 ---- */
    if (out->hw_len  > ARP_MAX_ADDR_LEN ||
        out->proto_len > ARP_MAX_ADDR_LEN)
        return -2;

    /* ---- 检查剩余数据是否够容纳 4 个地址字段 ---- */
    size_t need = (size_t)out->hw_len + (size_t)out->proto_len
                + (size_t)out->hw_len + (size_t)out->proto_len;
    if (len - offset < need)
        return -1;

    /* Sender Hardware Address */
    for (size_t i = 0; i < out->hw_len; i++)
        out->sender_hw[i] = data[offset + i];
    out->sender_hw_len = out->hw_len;
    offset += out->hw_len;

    /* Sender Protocol Address */
    for (size_t i = 0; i < out->proto_len; i++)
        out->sender_proto[i] = data[offset + i];
    out->sender_proto_len = out->proto_len;
    offset += out->proto_len;

    /* Target Hardware Address */
    for (size_t i = 0; i < out->hw_len; i++)
        out->target_hw[i] = data[offset + i];
    out->target_hw_len = out->hw_len;
    offset += out->hw_len;

    /* Target Protocol Address */
    for (size_t i = 0; i < out->proto_len; i++)
        out->target_proto[i] = data[offset + i];
    out->target_proto_len = out->proto_len;
    /* offset += out->proto_len; — 不必再用 */

    return 0;
}
