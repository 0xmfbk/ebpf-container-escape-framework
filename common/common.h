#ifndef COMMON_H
#define COMMON_H

// Field order matters: cgroup_id (u64) is placed FIRST so it is naturally
// 8-byte aligned at offset 0, meaning no compiler-inserted padding appears
// between any of the fields below it. The explicit `reserved` field makes
// the struct's true wire size (136 bytes) self-documenting instead of
// relying on implicit end-of-struct alignment padding — this must be
// mirrored exactly, field-for-field, in userspace/main.go's event_t,
// since encoding/binary.Read does NOT replicate C struct padding rules;
// it only reads the fields you declare, in the order you declare them.
// dest_ip/dest_port are appended after the original reserved[4] padding.
// Placement check: filename ends at offset 68+64=132, reserved[4] fills
// 132-136 (already 4-aligned). dest_ip (u32) at offset 136 is naturally
// 4-aligned (no gap needed). dest_port (u16) at 140 is naturally
// 2-aligned. reserved2[2] at 142 brings the struct to 144 bytes, which is
// a clean multiple of 8 (the struct's required alignment, driven by the
// u64 cgroup_id) — so no implicit compiler padding is introduced anywhere
// by this addition. Only set for Network_Connection events; zero
// otherwise.
struct event_t {
    __u64 cgroup_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8 comm[16];
    __u8 action[32];
    __u8 filename[64];
    __u8 reserved[4];
    // dest_ip is deliberately a raw 4-byte array, NOT a __u32. sin_addr
    // arrives in network byte order (= dotted-decimal order). If this
    // were a __u32, userspace's binary.Read (which reads the whole
    // struct as LittleEndian) would reinterpret these network-order
    // bytes as a little-endian host integer, scrambling the address —
    // this bit us once already (192.168.1.1 came out as 1.1.168.192,
    // an exact byte-reversal). A raw byte array sidesteps the ambiguity
    // entirely: there's no integer interpretation to get wrong.
    __u8 dest_ip[4];
    __u16 dest_port;   // destination port, HOST byte order (already converted in-kernel)
    __u8 reserved2[2]; // explicit tail padding; keeps sizeof == 144, 8-aligned
};

#endif
