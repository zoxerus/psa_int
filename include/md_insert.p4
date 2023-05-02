/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



/* -*- P4_16 -*- */
#ifndef __INT_TRANSIT__
#define __INT_TRANSIT__

#include "headers.p4"

control InsertMetadata (
        inout headers hdr, inout metadata meta,
        in    psa_egress_input_metadata_t  istd,
        inout psa_egress_output_metadata_t ostd
        ) 
    {
    
    DirectCounter<bit<32>>(PSA_CounterType_t.PACKETS) insert_counter;
    /* configure Node Role and set Node ID */
    action init_metadata(NodeID node_id) {
        insert_counter.count();
        meta.isTransit = true;
        meta.node_id = node_id;
    }

    /* Node ID, 4 bytes */
    @hidden
    action int_set_header_0() {
        hdr.int_node_id.setValid();
        hdr.int_node_id.node_id = meta.node_id;
    }
    
    /* L1 Interface Info, 4 byte each */
    @hidden
    action int_set_header_1() {
        hdr.int_l1_interfaces.setValid();
        hdr.int_l1_interfaces.ingress_id = (bit<16>) (hdr.umeta.ingress_port );
        hdr.int_l1_interfaces.egress_id = (bit<16>) ((bit<32>) istd.egress_port);
    }

    /* set Hope Latency 4 bytes */
    @hidden
    action int_set_header_2() {
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency = (bit<32>) (
            (bit<64>) istd.egress_timestamp - hdr.umeta.ingress_timestamp
        );
    }

    /* Queue Info 4 bytes, Currently not supported in PSA */
    @hidden
    action int_set_header_3() {
        // TODO: Support queue info
        hdr.int_queue_info.setValid();
        /* queue_id: 8 bits */
        hdr.int_queue_info.queue_id = 0;

        /* 
        queue occupancy 24 bits, not supported currently.
        use a random number instead ?
        */
        hdr.int_queue_info.queue_occupancy = 0;
    }

    /* Ingress Timestamp 8 bytes */
    @hidden
    action int_set_header_4() {
        hdr.int_ingress_timestamp.setValid();
        hdr.int_ingress_timestamp.ingress_timestamp =
            meta.ingress_timestamp;
    }

    /* Egress Timestamp 8 bytes */
    @hidden
    action int_set_header_5() {
        hdr.int_egress_timestamp.setValid();
        hdr.int_egress_timestamp.egress_timestamp =
            (bit<64>) istd.egress_timestamp;
    }

    /* L2 Port IDs 8 byte total 4 byte each */
    @hidden
    action int_set_header_6() {
        // TODO: Support L2 Port IDs.
        hdr.int_l2_interfaces.setValid();
        hdr.int_l2_interfaces.ingress_id = 0;
        hdr.int_l2_interfaces.egress_id = 0;
    }

    /* Egress Port Tx utilization */
    @hidden
    action int_set_header_7() { 
        // TODO: implement tx utilization support
        hdr.int_egress_tx.setValid();
        hdr.int_egress_tx.egress_tx_utilization = 0;
    }

    /* Buffer Info */
    @hidden
    action int_set_header_8() { 
        // TODO: implement buffer support
        hdr.int_buffer_info.setValid();
        hdr.int_buffer_info.buffer_id = 0;
        hdr.int_buffer_info.buffer_occupancy = 0;
    }

    // Actions to keep track of the new metadata added.
    @hidden
    action add_1() {
        meta.new_words = meta.new_words + 1;
        meta.new_bytes = meta.new_bytes + 4;
    }

    @hidden
    action add_2() {
        meta.new_words = meta.new_words + 2;
        meta.new_bytes = meta.new_bytes + 8;
    }

    @hidden
    action add_3() {
        meta.new_words = meta.new_words + 3;
        meta.new_bytes = meta.new_bytes + 12;
    }

    @hidden
    action add_4() {
        meta.new_words = meta.new_words + 4;
       meta.new_bytes = meta.new_bytes + 16;
    }

    @hidden
    action add_5() {
        meta.new_words = meta.new_words + 5;
        meta.new_bytes = meta.new_bytes + 20;
    }

    /* 
    actions for bits 0-3 combinations, 0 is msb, 3 is lsb
    Each bit set indicates that corresponding INT header should be added 
    */
    @hidden
     action int_set_header_0003_i0() {

     }
    @hidden
     action int_set_header_0003_i1() {
        int_set_header_3();
        add_1();
    }
    @hidden
    action int_set_header_0003_i2() {
        int_set_header_2();
        add_1();
    }
    @hidden
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
        add_2();
    }
    @hidden
    action int_set_header_0003_i4() {
        int_set_header_1();
        add_1();
    }
    @hidden
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
        add_2();
    }
    @hidden
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
        add_2();
    }
    @hidden
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        add_3();
    }
    @hidden
    action int_set_header_0003_i8() {
        int_set_header_0();
        add_1();
    }
    @hidden
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_4();
    }

     /* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
    @hidden
    action int_set_header_0407_i0() {
        
    }
    @hidden
    action int_set_header_0407_i1() {
        int_set_header_7();
        add_1();
    }
    @hidden
    action int_set_header_0407_i2() {
        int_set_header_6();
        add_2();
    }
    @hidden
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
        add_3();
    }
    @hidden
    action int_set_header_0407_i4() {
        int_set_header_5();
        add_1();
    }
    @hidden
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
        add_2();
    }
    @hidden
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
        add_3();
    }
    @hidden
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        add_4();
    }
    @hidden
    action int_set_header_0407_i8() {
        int_set_header_4();
        add_1();
    }
    @hidden
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
        add_2();
    }
    @hidden
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
        add_3();
    }
    @hidden
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
        add_4();
    }
    @hidden
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
        add_2();
    }
    @hidden
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
        add_3();
    }
    @hidden
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_4();
    }
    @hidden
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_5();
    }

    // Default action used to set switch ID.
    table tb_int_insert {
        // We don't really need a key here, however we add a dummy one as a
        // workaround to ONOS inability to properly support default actions.
        key = {
            hdr.int_shim.isValid(): exact;
        }
        actions = {
            init_metadata;
            NoAction;
        }
        default_action = NoAction;
        psa_direct_counter = insert_counter;
        size = 100;
    }

    /* Table to process instruction bits 0-3 */
    @hidden
    table tb_int_inst_0003 {
        key = {
            hdr.int_md.instruction_bitmap_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        const entries = {
            (0x0) : int_set_header_0003_i0();
            (0x1) : int_set_header_0003_i1();
            (0x2) : int_set_header_0003_i2();
            (0x3) : int_set_header_0003_i3();
            (0x4) : int_set_header_0003_i4();
            (0x5) : int_set_header_0003_i5();
            (0x6) : int_set_header_0003_i6();
            (0x7) : int_set_header_0003_i7();
            (0x8) : int_set_header_0003_i8();
            (0x9) : int_set_header_0003_i9();
            (0xA) : int_set_header_0003_i10();
            (0xB) : int_set_header_0003_i11();
            (0xC) : int_set_header_0003_i12();
            (0xD) : int_set_header_0003_i13();
            (0xE) : int_set_header_0003_i14();
            (0xF) : int_set_header_0003_i15();
        }
    }

    /* Table to process instruction bits 4-7 */
    @hidden
    table tb_int_inst_0407 {
        key = {
            hdr.int_md.instruction_bitmap_0407 : exact;
        }
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
        }
        const entries = {
            (0x0) : int_set_header_0407_i0();
            (0x1) : int_set_header_0407_i1();
            (0x2) : int_set_header_0407_i2();
            (0x3) : int_set_header_0407_i3();
            (0x4) : int_set_header_0407_i4();
            (0x5) : int_set_header_0407_i5();
            (0x6) : int_set_header_0407_i6();
            (0x7) : int_set_header_0407_i7();
            (0x8) : int_set_header_0407_i8();
            (0x9) : int_set_header_0407_i9();
            (0xA) : int_set_header_0407_i10();
            (0xB) : int_set_header_0407_i11();
            (0xC) : int_set_header_0407_i12();
            (0xD) : int_set_header_0407_i13();
            (0xE) : int_set_header_0407_i14();
            (0xF) : int_set_header_0407_i15();
        }
    }

    apply {

        /* 
        a table for setting switch id and role in the local_metadata.
        */
        if (tb_int_insert.apply().hit) {
            /*
            tb_int_inst_0003 is for bits 0-3 of the instruction bitmap
            tb_int_inst_0407 is for bits 4-7 of the instruction bitmap
            read the instructions from the INT header and append metadata.
            */
            tb_int_inst_0003.apply();
            tb_int_inst_0407.apply();

            // Decrement remaining hop count
            hdr.int_md.remaining_hop_count = hdr.int_md.remaining_hop_count - 1;

            // Update headers lengths.

            hdr.ipv4.totallen = hdr.ipv4.totallen + meta.new_bytes;


            hdr.udp.length_ = hdr.udp.length_ + meta.new_bytes;


            hdr.int_shim.int_total_length = hdr.int_shim.int_total_length + meta.new_words;
        }
    }
}

#endif
