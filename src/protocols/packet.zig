const pcap = @import("pcap");

const ethernet = @import("ethernet.zig");
const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");
const tcp = @import("tcp.zig");
const udp = @import("udp.zig");
const icmp = @import("icmp.zig");

pub const DecodeError = error{
    UnsupportedLinkType,
};

pub const DecodedPacket = struct {
    ethernet: ?ethernet.EthernetFrame = null,
    ipv4: ?ipv4.Ipv4Packet = null,
    ipv6: ?ipv6.Ipv6Packet = null,
    tcp: ?tcp.TcpSegment = null,
    udp: ?udp.UdpDatagram = null,
    icmp: ?icmp.Icmp = null,

    pub fn decode(data: []const u8, linktype: pcap.LinkType) DecodeError!DecodedPacket {
        var pkt = DecodedPacket{};

        var next_data: []const u8 = data;

        // Layer 2
        switch (linktype) {
            .ethernet => {
                pkt.ethernet = ethernet.parse(next_data) catch return pkt;
                next_data = pkt.ethernet.?.payload;
            },
            else => return DecodeError.UnsupportedLinkType,
        }

        // Layer 3
        switch (pkt.ethernet.?.ether_type) {
            .ipv4 => {
                pkt.ipv4 = ipv4.parse(next_data) catch return pkt;
                next_data = pkt.ipv4.?.payload;
            },
            .ipv6 => {
                pkt.ipv6 = ipv6.parse(next_data) catch return pkt;
                next_data = pkt.ipv6.?.payload;
            },
            else => return pkt,
        }

        // Layer 4
        if (pkt.ipv4) |ip4| {
            switch (ip4.protocol) {
                .tcp => pkt.tcp = tcp.parse(next_data) catch null,
                .udp => pkt.udp = udp.parse(next_data) catch null,
                .icmp => pkt.icmp = icmp.Icmp.parse(.v4, next_data) catch null,
                else => {},
            }
        } else if (pkt.ipv6) |ip6| {
            switch (ip6.next_header) {
                .tcp => pkt.tcp = tcp.parse(next_data) catch null,
                .udp => pkt.udp = udp.parse(next_data) catch null,
                .icmpv6 => pkt.icmp = icmp.Icmp.parse(.v6, next_data) catch null,
                else => {},
            }
        }

        return pkt;
    }
};
