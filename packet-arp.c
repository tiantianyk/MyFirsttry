/* packet-arp.c
 * Wireshark dissector plugin for Address Resolution Protocol (ARP)
 *
 * 架构说明:
 *   本 dissector 将解析逻辑委托给独立的 arp_decode() 函数（arp_decode.h/c），
 *   dissect_arp() 只负责把解析结果填入 Wireshark 协议树。
 *   这样做的目的是让 ARP 解析逻辑可复用——不依赖 Wireshark 框架也能单独使用。
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <wsutil/str_util.h>

#include "arp_decode.h"

/* Protocol handle */
static int proto_arp = -1;

/* Header field handles */
static int hf_arp_hrd_type  = -1;
static int hf_arp_pro_type  = -1;
static int hf_arp_hln       = -1;
static int hf_arp_pln       = -1;
static int hf_arp_opcode    = -1;
static int hf_arp_sha       = -1;
static int hf_arp_spa       = -1;
static int hf_arp_tha       = -1;
static int hf_arp_tpa       = -1;

/* Expert info handles */
static expert_field ei_arp_unknown_hardware  = EI_INIT;
static expert_field ei_arp_unknown_protocol  = EI_INIT;
static expert_field ei_arp_unknown_opcode    = EI_INIT;
static expert_field ei_arp_malformed         = EI_INIT;

/* Subtree handle */
static gint ett_arp = -1;

/* ---------- Hardware Type table ---------- */
static const value_string arp_hardware_type_vals[] = {
    { 1,    "Ethernet (10Mb)" },
    { 2,    "Experimental Ethernet (3Mb)" },
    { 3,    "Amateur Radio AX.25" },
    { 4,    "Proteon ProNET Token Ring" },
    { 5,    "Chaos" },
    { 6,    "IEEE 802 Networks" },
    { 7,    "ARCNET" },
    { 8,    "Hyperchannel" },
    { 9,    "Lanstar" },
    { 10,   "Autonet Short Address" },
    { 11,   "LocalTalk" },
    { 12,   "LocalNet (IBM PCNet / SYTEK)" },
    { 13,   "Ultra link" },
    { 14,   "SMDS" },
    { 15,   "Frame Relay" },
    { 16,   "Asynchronous Transmission Mode (ATM)" },
    { 17,   "HDLC" },
    { 18,   "Fibre Channel" },
    { 19,   "Asynchronous Transmission Mode (ATM)" },
    { 20,   "Serial Line" },
    { 21,   "Asynchronous Transmission Mode (ATM)" },
    { 22,   "MIL-STD-188-220" },
    { 23,   "Metricom" },
    { 24,   "IEEE 1394.1995" },
    { 25,   "MAPOS" },
    { 26,   "Twinaxial" },
    { 27,   "EUI-64" },
    { 28,   "HIPARP" },
    { 29,   "IP and ARP over ISO 7816-3" },
    { 30,   "ARPSec" },
    { 31,   "IPsec tunnel" },
    { 32,   "InfiniBand" },
    { 33,   "TCM over Loongson" },
    { 0, NULL }
};

/* ---------- Protocol Type table ---------- */
static const value_string arp_protocol_type_vals[] = {
    { 0x0800, "IPv4" },
    { 0x0806, "ARP" },
    { 0x8035, "RARP" },
    { 0x86DD, "IPv6" },
    { 0, NULL }
};

/* ---------- Opcode table ---------- */
static const value_string arp_opcode_vals[] = {
    { 1, "Request" },
    { 2, "Reply" },
    { 3, "Request Reverse" },
    { 4, "Reply Reverse" },
    { 5, "DRARP-Request" },
    { 6, "DRARP-Reply" },
    { 7, "DRARP-Error" },
    { 8, "InARP-Request" },
    { 9, "InARP-Reply" },
    { 10, "ARP-NAK" },
    { 0, NULL }
};

/* ---------- Core dissection function ---------- */
static int
dissect_arp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item   *ti;
    proto_tree   *arp_tree;
    gint          offset = 0;
    arp_packet_t  arp;
    int           decode_ret;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* ===========================================================
     * Step 1: 委托给纯 C 的 arp_decode() 解析原始字节
     *         拿到结构化的 arp_packet_t，后续全部用它驱动
     * =========================================================== */
    {
        const guint8 *raw = tvb_get_ptr(tvb, 0, tvb_captured_length(tvb));
        decode_ret = arp_decode(raw, tvb_captured_length(tvb), &arp);
    }

    if (decode_ret == -2) {
        proto_tree_add_expert(tree, pinfo, &ei_arp_malformed, tvb, 0, -1);
        col_add_str(pinfo->cinfo, COL_INFO, "Malformed ARP (address length too large)");
        return tvb_captured_length(tvb);
    }
    if (decode_ret != 0) {
        proto_tree_add_expert(tree, pinfo, &ei_arp_malformed, tvb, 0, -1);
        col_add_str(pinfo->cinfo, COL_INFO, "Truncated ARP");
        return tvb_captured_length(tvb);
    }

    /* ---- Build summary line ---- */
    {
        const char *op_name = val_to_str_const(arp.opcode, arp_opcode_vals, "Unknown");

        if (arp.opcode == ARP_OP_REQUEST) {
            if (arp.proto_len == 4)
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Who has %s?  Tell %s",
                    get_hostname(arp.target_proto),
                    get_hostname(arp.sender_proto));
            else
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Who has %s?  Tell %s",
                    bytes_to_str(wmem_packet_scope(), arp.target_proto, arp.proto_len),
                    bytes_to_str(wmem_packet_scope(), arp.sender_proto, arp.proto_len));

        } else if (arp.opcode == ARP_OP_REPLY) {
            if (arp.proto_len == 4)
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "%s is at %s",
                    get_hostname(arp.sender_proto),
                    bytes_to_str(wmem_packet_scope(), arp.sender_hw, arp.hw_len));
            else
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "%s is at %s",
                    bytes_to_str(wmem_packet_scope(), arp.sender_proto, arp.proto_len),
                    bytes_to_str(wmem_packet_scope(), arp.sender_hw, arp.hw_len));

        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s", op_name);
        }
    }

    /* ---- Build protocol tree ---- */
    ti = proto_tree_add_item(tree, proto_arp, tvb, 0, -1, ENC_NA);
    arp_tree = proto_item_add_subtree(ti, ett_arp);

    /* Hardware Type */
    proto_tree_add_item(arp_tree, hf_arp_hrd_type, tvb, 0, 2, ENC_BIG_ENDIAN);
    if (!try_val_to_str(arp.hw_type, arp_hardware_type_vals))
        expert_add_info(pinfo, ti, &ei_arp_unknown_hardware);
    offset = 2;

    /* Protocol Type */
    proto_tree_add_item(arp_tree, hf_arp_pro_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (!try_val_to_str(arp.proto_type, arp_protocol_type_vals))
        expert_add_info(pinfo, ti, &ei_arp_unknown_protocol);
    offset += 2;

    /* Hardware Size & Protocol Size */
    proto_tree_add_item(arp_tree, hf_arp_hln, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(arp_tree, hf_arp_pln, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Opcode */
    proto_tree_add_item(arp_tree, hf_arp_opcode, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (!try_val_to_str(arp.opcode, arp_opcode_vals))
        expert_add_info(pinfo, ti, &ei_arp_unknown_opcode);
    offset += 2;

    /* Sender Hardware Address */
    proto_tree_add_item(arp_tree, hf_arp_sha, tvb, offset, arp.hw_len, ENC_NA);
    offset += arp.hw_len;

    /* Sender Protocol Address */
    proto_tree_add_item(arp_tree, hf_arp_spa, tvb, offset, arp.proto_len, ENC_BIG_ENDIAN);
    offset += arp.proto_len;

    /* Target Hardware Address */
    proto_tree_add_item(arp_tree, hf_arp_tha, tvb, offset, arp.hw_len, ENC_NA);
    offset += arp.hw_len;

    /* Target Protocol Address */
    proto_tree_add_item(arp_tree, hf_arp_tpa, tvb, offset, arp.proto_len, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* ---------- Registration ---------- */
void
proto_register_arp(void)
{
    static hf_register_info hf[] = {
        { &hf_arp_hrd_type,
          { "Hardware Type",           "arp.hw.type",
            FT_UINT16, BASE_DEC, VALS(arp_hardware_type_vals), 0x0,
            "Hardware address type (e.g., Ethernet)", HFILL }
        },
        { &hf_arp_pro_type,
          { "Protocol Type",           "arp.proto.type",
            FT_UINT16, BASE_HEX, VALS(arp_protocol_type_vals), 0x0,
            "Protocol address type (e.g., IPv4)", HFILL }
        },
        { &hf_arp_hln,
          { "Hardware Size",           "arp.hw.size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of hardware address (bytes)", HFILL }
        },
        { &hf_arp_pln,
          { "Protocol Size",           "arp.proto.size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of protocol address (bytes)", HFILL }
        },
        { &hf_arp_opcode,
          { "Opcode",                  "arp.opcode",
            FT_UINT16, BASE_DEC, VALS(arp_opcode_vals), 0x0,
            "ARP operation code (request / reply)", HFILL }
        },
        { &hf_arp_sha,
          { "Sender MAC Address",      "arp.src.hw",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Sender hardware (MAC) address", HFILL }
        },
        { &hf_arp_spa,
          { "Sender IP Address",       "arp.src.proto",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            "Sender protocol (IP) address", HFILL }
        },
        { &hf_arp_tha,
          { "Target MAC Address",      "arp.dst.hw",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Target hardware (MAC) address", HFILL }
        },
        { &hf_arp_tpa,
          { "Target IP Address",       "arp.dst.proto",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            "Target protocol (IP) address", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_arp,
    };

    static ei_register_info ei[] = {
        { &ei_arp_unknown_hardware,
          { "arp.hw.type.unknown", PI_PROTOCOL, PI_WARN,
            "Unknown hardware type", EXPFILL }
        },
        { &ei_arp_unknown_protocol,
          { "arp.proto.type.unknown", PI_PROTOCOL, PI_WARN,
            "Unknown protocol type", EXPFILL }
        },
        { &ei_arp_unknown_opcode,
          { "arp.opcode.unknown", PI_PROTOCOL, PI_WARN,
            "Unknown ARP opcode", EXPFILL }
        },
        { &ei_arp_malformed,
          { "arp.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed ARP packet", EXPFILL }
        },
    };

    expert_module_t *expert_arp;

    proto_arp = proto_register_protocol(
        "Address Resolution Protocol",
        "ARP",
        "arp");

    proto_register_field_array(proto_arp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_arp = expert_register_protocol(proto_arp);
    expert_register_field_array(expert_arp, ei, array_length(ei));
}

/* ---------- Handoff ---------- */
void
proto_reg_handoff_arp(void)
{
    dissector_handle_t arp_handle;

    arp_handle = create_dissector_handle(dissect_arp, proto_arp);
    dissector_add_uint("ethertype", ETHERTYPE_ARP, arp_handle);
}
