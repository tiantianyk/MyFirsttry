/* packet-wm.c
 * Wireshark dissector plugin for WM Protocol
 *
 * Architecture:
 *   This dissector delegates parsing logic to wm_decode() function (wm_decode.h/c),
 *   dissect_wm() only fills the parsed results into Wireshark protocol tree.
 *   This allows WM parsing logic to be reusable without Wireshark framework.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "wm_decode.h"

static int proto_wm = -1;

static int hf_wm_header             = -1;
static int hf_wm_next_hop_id        = -1;
static int hf_wm_prev_hop_id        = -1;
static int hf_wm_msg_type           = -1;
static int hf_wm_msg_subtype        = -1;
static int hf_wm_trans_mode         = -1;
static int hf_wm_qos_priority       = -1;
static int hf_wm_ttl                = -1;
static int hf_wm_src_node_id        = -1;
static int hf_wm_reserved           = -1;

static expert_field ei_wm_malformed = EI_INIT;

static gint ett_wm = -1;
static gint ett_wm_bits = -1;

static dissector_handle_t arp_handle = NULL;

static const value_string wm_msg_type_vals[] = {
    { 0x0, "Internal Message" },
    { 0x1, "Frequency Message" },
    { 0, NULL }
};

static const value_string wm_msg_subtype_vals[] = {
    { 0x0, "HELLO / Internal / Command" },
    { 0x1, "TC / Sync Broadcast / Data" },
    { 0x2, "HNA" },
    { 0, NULL }
};

static const value_string wm_trans_mode_vals[] = {
    { 0, "Unicast" },
    { 1, "Broadcast" },
    { 0, NULL }
};

static const value_string wm_qos_priority_vals[] = {
    { 0, "Priority 1 (Lowest)" },
    { 1, "Priority 2" },
    { 2, "Priority 3" },
    { 3, "Priority 4" },
    { 4, "Priority 5" },
    { 5, "Priority 6" },
    { 6, "Priority 7" },
    { 7, "Priority 8 (Highest)" },
    { 0, NULL }
};

/* Bitmask fields array for proto_tree_add_bitmask */
static const int *wm_bitmask_fields[] = {
    &hf_wm_next_hop_id,
    &hf_wm_prev_hop_id,
    &hf_wm_msg_type,
    &hf_wm_msg_subtype,
    &hf_wm_trans_mode,
    &hf_wm_qos_priority,
    &hf_wm_ttl,
    &hf_wm_src_node_id,
    &hf_wm_reserved,
    NULL
};

static int
dissect_wm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *wm_tree;
    wm_packet_t wm;
    int decode_ret;
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WM");
    col_clear(pinfo->cinfo, COL_INFO);

    {
        const guint8 *raw = tvb_get_ptr(tvb, 0, tvb_captured_length(tvb));
        decode_ret = wm_decode(raw, tvb_captured_length(tvb), &wm);
    }

    if (decode_ret != 0) {
        proto_tree_add_expert(tree, pinfo, &ei_wm_malformed, tvb, 0, -1);
        col_add_str(pinfo->cinfo, COL_INFO, "Truncated WM");
        return tvb_captured_length(tvb);
    }

    {
        const char *type_name = val_to_str_const(wm.msg_type, wm_msg_type_vals, "Unknown");
        const char *subtype_name = val_to_str_const(wm.msg_subtype, wm_msg_subtype_vals, "Unknown");
        col_add_fstr(pinfo->cinfo, COL_INFO,
            "%s: %s, Src:%u, Next:%u, TTL:%u",
            type_name, subtype_name, wm.src_node_id, wm.next_hop_id, wm.ttl);
    }

    ti = proto_tree_add_item(tree, proto_wm, tvb, 0, WM_HEADER_LEN, ENC_NA);
    wm_tree = proto_item_add_subtree(ti, ett_wm);

    /* Use proto_tree_add_bitmask_len to parse all bit fields in one call
     * Header is 5 bytes (40 bits), need to specify length explicitly */
    proto_tree_add_bitmask_len(wm_tree, tvb, 0, WM_HEADER_LEN, hf_wm_header, ett_wm_bits, wm_bitmask_fields, ENC_BIG_ENDIAN);

    offset = WM_HEADER_LEN;

    /* If trans_mode == 1 (Broadcast), call ARP dissector for remaining bytes */
    if (wm.trans_mode == WM_TRANS_MODE_BROADCAST) {
        tvbuff_t *next_tvb;
        int remaining_len = tvb_captured_length_remaining(tvb, offset);

        if (remaining_len > 0 && arp_handle != NULL) {
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(arp_handle, next_tvb, pinfo, tree);
            offset += remaining_len;
        }
    }

    /* Restore WM protocol info - ARP dissector may have overwritten COL_INFO */
    {
        const char *type_name = val_to_str_const(wm.msg_type, wm_msg_type_vals, "Unknown");
        const char *subtype_name = val_to_str_const(wm.msg_subtype, wm_msg_subtype_vals, "Unknown");
        col_add_fstr(pinfo->cinfo, COL_INFO,
            "%s: %s, Src:%u, Next:%u, TTL:%u",
            type_name, subtype_name, wm.src_node_id, wm.next_hop_id, wm.ttl);
    }

    return offset;
}

void
proto_register_wm(void)
{
    static hf_register_info hf[] = {
        { &hf_wm_header,
          { "WM Header",                  "wm.header",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            "WM protocol header (40 bits)", HFILL }
        },
        { &hf_wm_next_hop_id,
          { "Next Hop Node ID",           "wm.next_hop_id",
            FT_UINT64, BASE_DEC, NULL, 0xFE00000000,
            "Next hop node ID", HFILL }
        },
        { &hf_wm_prev_hop_id,
          { "Prev Hop Node ID",           "wm.prev_hop_id",
            FT_UINT64, BASE_DEC, NULL, 0x01FC000000,
            "Previous hop node ID", HFILL }
        },
        { &hf_wm_msg_type,
          { "Message Type",               "wm.msg_type",
            FT_UINT64, BASE_DEC, VALS(wm_msg_type_vals), 0x0003C00000,
            "Module message type", HFILL }
        },
        { &hf_wm_msg_subtype,
          { "Message Subtype",            "wm.msg_subtype",
            FT_UINT64, BASE_DEC, VALS(wm_msg_subtype_vals), 0x00003C0000,
            "Message subtype", HFILL }
        },
        { &hf_wm_trans_mode,
          { "Transport Mode",             "wm.trans_mode",
            FT_UINT64, BASE_DEC, VALS(wm_trans_mode_vals), 0x0000020000,
            "0: Unicast, 1: Broadcast", HFILL }
        },
        { &hf_wm_qos_priority,
          { "QoS Priority",               "wm.qos_priority",
            FT_UINT64, BASE_DEC, VALS(wm_qos_priority_vals), 0x000001C000,
            "QoS priority 0~7", HFILL }
        },
        { &hf_wm_ttl,
          { "TTL (Time to Live)",         "wm.ttl",
            FT_UINT64, BASE_DEC, NULL, 0x0000003F00,
            "Packet lifetime", HFILL }
        },
        { &hf_wm_src_node_id,
          { "Source Node ID",             "wm.src_node_id",
            FT_UINT64, BASE_DEC, NULL, 0x00000000FE,
            "Source node ID", HFILL }
        },
        { &hf_wm_reserved,
          { "Reserved",                   "wm.reserved",
            FT_UINT64, BASE_DEC, NULL, 0x0000000001,
            "Reserved bit", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_wm,
        &ett_wm_bits,
    };

    static ei_register_info ei[] = {
        { &ei_wm_malformed,
          { "wm.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed WM packet", EXPFILL }
        },
    };

    expert_module_t *expert_wm;

    proto_wm = proto_register_protocol(
        "WM Protocol",
        "WM",
        "wm");

    proto_register_field_array(proto_wm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_wm = expert_register_protocol(proto_wm);
    expert_register_field_array(expert_wm, ei, array_length(ei));
}

void
proto_reg_handoff_wm(void)
{
    dissector_handle_t wm_handle;

    wm_handle = create_dissector_handle(dissect_wm, proto_wm);
    dissector_add_uint("udp.port", 9999, wm_handle);

    /* Get ARP dissector handle for chaining */
    arp_handle = find_dissector("arp");
}