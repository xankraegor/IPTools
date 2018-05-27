//
//  IPTools
//
//  Created by Xan Kraegor on 08.05.2018.
//  Copyright © 2018 Xan Kraegor. All rights reserved.
//

import Foundation

struct IPAddress: CustomStringConvertible {
    
    public let ipAddr: [UInt8]
    public let ipDecimal: UInt32
    
    /// Initializes IPAddress with a string
    /// - parameters:
    ///     - string: Example: "112.99.210.4"
    init?(_ string: String) {
        let parts = string
            .split(separator: Character("."))
            .map({String($0)})
        let oct = parts.compactMap({ UInt8($0) })
        guard oct.count == 4 else { return nil }
        ipAddr = oct
        let ipo = oct.map({ UInt32($0) })
        ipDecimal = (ipo[0] << 24) | (ipo[1] << 16) | (ipo[2] << 8) | ipo[3]
    }
    
    /// Initializes IPAddress with a UInt32 value
    /// - parameters:
    ///     - decimal: Example: 12345678 or 0hF1AC0015 or 0b01100101_11111111_00000000_11010111
    init(decimal dec: UInt32) {
        var bigEndian = dec.bigEndian
        let count = MemoryLayout<UInt32>.size
        let bytePtr = withUnsafePointer(to: &bigEndian) {
            $0.withMemoryRebound(to: UInt8.self, capacity: count) {
                UnsafeBufferPointer(start: $0, count: count)
            }
        }
        ipAddr = Array(bytePtr)
        ipDecimal = dec
    }
    
    /// Initializes IPAddress with a UInt8 decimal values
    /// - parameters:
    ///     - ipDecimals: Example: [127, 0, 0, 1]
    init?(ipDecimals dec: [UInt8]) {
        guard dec.count == 4 else { return nil }
        ipAddr = dec
        let ipo = dec.map({ UInt32($0) })
        ipDecimal = (ipo[0] << 24) | (ipo[1] << 16) | (ipo[2] << 8) | ipo[3]
    }
    
    // MARK: - CustomStringConvertible
    
    var description: String {
        return "\(ipAddr[0]).\(ipAddr[1]).\(ipAddr[2]).\(ipAddr[3])"
    }
    
    // MARK: - Special address check
    
    private func isInRange(_ lo: UInt32, to: UInt32)->Bool {
        return ipDecimal >= lo && ipDecimal <= to
    }
    
    /// Indicates wheter the IP address lies within bounds of private-use range.
    /// See RFC1918 for details (http://www.iana.org/go/rfc1918)
    var isPrivate: Bool {
        return isInRange(167772160, to: 184549375) || // 10.0.0.0/8
            isInRange(2886729728, to: 2887778303) || // 172.16.0.0/12
            isInRange(3232235520, to: 3232301055) // 192.168.0.0/16
    }
    
    /// Indicates wheter the IP address lies within bounds of "This host on this network" range.
    /// See RFC1122, Section 3.2.1.3 for details (http://www.iana.org/go/rfc1122)
    var isThisNetworkReserved: Bool {
        return isInRange(0, to: 16777215) // 0.0.0.0/8
    }
    
    /// Indicates wheter the IP address lies within bounds of loopback range.
    /// See RFC1122, Section 3.2.1.3 for details (http://www.iana.org/go/rfc1122)
    var isLoopback: Bool {
        return isInRange(2130706432, to: 2147483647) // 127.0.0.0/8
    }
    
    /// Indicates wheter the IP address lies within bounds of link local range.
    /// See RFC3927 for details (http://www.iana.org/go/rfc3927)
    var isLinkLocal: Bool {
        return isInRange(2851995648, to: 2852061183) //169.254.0.0/16
    }
    
    /// Indicates wheter the IP address lies within bounds of shared address space.
    /// See RFC6598 for details (http://www.iana.org/go/rfc6598)
    var isSharedAddressSpace: Bool {
        return isInRange(1681915904, to: 1686110207) // 100.64.0.0/10
    }
    
    /// Indicates wheter the IP address lies within bounds of reserved address space.
    /// See RFC1112, Section 4 for details (http://www.iana.org/go/rfc1112)
    var isReserved: Bool {
        return isInRange(4026531840, to: 4294967295) // 240.0.0.0/4
    }
    
    /// Indicates wheter the IP address lies within bounds of IETF assigned address space.
    /// See RFC6890, Section 2.1 for details (http://www.iana.org/go/rfc6890)
    var isIETFAssigned: Bool {
        return isInRange(3221225472, to: 3221225727) // 192.0.0.0/24
    }
    
    /// Indicates wheter the IP address lies within bounds of TEST-NET-1 address space.
    /// See RFC5737 for details (http://www.iana.org/go/rfc5737)
    var isTestNet1: Bool {
        return isInRange(3221225984, to: 3221226239) // 192.0.2.0/24
    }
    
    /// Indicates wheter the IP address lies within bounds of TEST-NET-2 address space.
    /// See RFC5737 for details (http://www.iana.org/go/rfc5737)
    var isTestNet2: Bool {
        return isInRange(3325256704, to: 3325256959) // 198.51.100.0/24
    }
    
    /// Indicates wheter the IP address lies within bounds of TEST-NET-2 address space.
    /// See RFC5737 for details (http://www.iana.org/go/rfc5737)
    var isTestNet3: Bool {
        return isInRange(3405803776, to: 3405804031) // 203.0.113.0/24
    }
    
    /// Indicates wheter the IP address lies within bounds of benchmarking address space.
    /// See RFC2544 for details (http://www.iana.org/go/rfc2544)
    var isBenchmarking: Bool {
        return isInRange(3323068416, to: 3323199487) // 198.18.0.0/15
    }
    
    /// Indicates wheter the IP address can be globally reachable
    var isSpecialNonGlobal: Bool {
        return isPrivate || isLoopback || isReserved || isTestNet1 || isTestNet2 || isTestNet3 || isLinkLocal || isIETFAssigned || isBenchmarking || isThisNetworkReserved ||
        isSharedAddressSpace
    }
}

// MARK: - Equatable

extension IPAddress: Equatable {
    
    static func == (lhs: IPAddress, rhs: IPAddress) -> Bool {
        return lhs.ipDecimal == rhs.ipDecimal
    }
    
}

// MARK: - Comparable

extension IPAddress: Comparable {
    
    static func < (lhs: IPAddress, rhs: IPAddress) -> Bool {
        return lhs.ipDecimal < rhs.ipDecimal
    }
    
}


// MARK: - IPRangeProtocol

extension IPAddress: IPRangeProtocol {
    
    var rngLow: IPAddress {
        return self
    }
    
    var rngHigh: IPAddress {
        return self
    }
    
}

//==================================================================================================

/// Represents an address in network /0 to /31 if it's not equal to the first
/// address in the subnet or whole subnet otherwise.
/// A /32 case is always one-IP-subnet by design.
struct IPRoute {
    
    public let ip: IPAddress
    public let prefix: UInt8
    public let prefixDecimal: UInt32
    
    /// Initializes IPRoute (IP address and network prefix) with a string
    /// - parameters:
    ///     - string: Example: "112.99.210.4/24"
    init?(_ str: String) {
        let parts = str.split(separator: "/").map{String($0)}
        guard parts.count == 1 || parts.count == 2 else { return nil }
        guard let iptmp = IPAddress(parts[0]) else { return nil }
        ip = iptmp
        
        if parts.count == 2, let pr = UInt8(parts[1]), pr <= 32 {
            prefix = pr
            prefixDecimal = ~(UInt32.max >> prefix)
        } else {
            prefix = 32
            prefixDecimal = UInt32.max
        }
    }
    
    /// Initializes IPRoute with an IP address instance and network prefix
    /// - parameters:
    ///     - withIPAddr: IPAddress instance
    ///     - prefix: network prefix as an unsigned integer. should be less or equal 32.
    init?<T: UnsignedInteger>(withIPAddr: IPAddress, prefix: T) {
        guard prefix <= 32 else { return nil }
        self.prefix = UInt8(prefix)
        ip = IPAddress(decimal: withIPAddr.ipDecimal)
        prefixDecimal = ~(UInt32.max >> prefix)
    }
    
    /// Initializes IPRoute with a set of 4 IP octets (decimals) and network prefix
    /// - parameters:
    ///     - withIpDecimals: array of four unsigned integers of any type
    ///     - prefix: network prefix as an unsigned integer. Should be less or equal 32.
    init?<T: UnsignedInteger>(withIpDeciamals dec: [UInt8], prefix: T) {
        guard dec.count == 4, prefix <= 32 else { return nil }
        self.prefix = UInt8(prefix)
        guard let iptmp = IPAddress(ipDecimals: dec) else { return nil }
        ip = iptmp
        prefixDecimal = ~(UInt32.max >> prefix)
    }
    
    // MARK: - Decimal UInt32 numbers
    
    /// Cisco-compliant inverted netmask for firewall configuration purposes
    public var wildcardDecimal: UInt32 {
        return UInt32.max >> prefix
    }
    
    /// Decimal number of the first address in the subnet
    public var networkDecimal: UInt32 {
        return ip.ipDecimal & prefixDecimal
    }
    
    /// Decimal number of the last address in the subnet
    public var broadcastDecimal: UInt32 {
        return ip.ipDecimal | wildcardDecimal
    }
    
    // MARK: - String representations
    
    /// Converts UInt32 to the traditional IP address string i.e. "127.0.0.1"
    public static func ipDeciamalToString(dec: UInt32)->String {
        var bigEndian = dec.bigEndian
        let count = MemoryLayout<UInt32>.size
        let bytePtr = withUnsafePointer(to: &bigEndian) {
            $0.withMemoryRebound(to: UInt8.self, capacity: count) {
                UnsafeBufferPointer(start: $0, count: count)
            }
        }
        return Array(bytePtr).map({String($0)}).joined(separator: ".")
    }
    
    /// String of the subnet prefix mask as of before CIDR notation i.e. "255.255.255.0"
    public var prefixString: String {
        return IPRoute.ipDeciamalToString(dec: prefixDecimal)
    }
    
    /// Cisco-compliant inverted netmask string i.e. "0.0.0.255"
    public var wildcardString: String {
        return IPRoute.ipDeciamalToString(dec: wildcardDecimal)
    }
    
    /// IP address which the subnet begins with, represents network itself
    public var networkString: String {
        return IPRoute.ipDeciamalToString(dec: networkDecimal)
    }
    
    /// The subnet's last IP address used for broadcasting of frames
    public var broadcastString: String {
        return IPRoute.ipDeciamalToString(dec: broadcastDecimal)
    }
    
    // MARK: - Subnetting & Supernetting
    
    /// Count of IP addresses witin the subnet
    public var ipAddressCount: UInt32 {
        return broadcastDecimal - networkDecimal + 1
    }
    
    /// Indicates wheter the subnet incudes the second one or is equal to the second
    public func subnetIncludes(second: IPRoute)->Bool {
        return (self.networkDecimal <= second.networkDecimal) && self.broadcastDecimal >= second.broadcastDecimal
    }
    
    private func overlapsDecimalRange(_ low: UInt32, to high: UInt32)->Bool {
        return (networkDecimal <= low && broadcastDecimal >= low) || (networkDecimal <= high && broadcastDecimal >= high)
    }
    
    /// Shows whether the subnet is at least partially incuded in the second
    public func subnetOverlaps(second: IPRoute)->Bool {
        return (self.networkDecimal <= second.networkDecimal && self.broadcastDecimal >= second.networkDecimal) ||
            (second.networkDecimal <= self.networkDecimal && second.broadcastDecimal >= self.networkDecimal)
    }
    
    /// Produces sum of two subnets with equal prefixes if possible or nil otherwise
    public func summarize(second: IPRoute)->IPRoute? {
        guard self.prefix > 0 else { return self }
        guard !(self == second) else { return self }
        guard self.prefix == second.prefix else { return nil }
        guard let supernet = IPRoute(withIpDeciamals: self.ip.ipAddr, prefix: self.prefix - 1),
            let testRt = IPRoute(withIPAddr: IPAddress(decimal: supernet.broadcastDecimal), prefix: self.prefix) else { return nil }
        return (testRt.networkDecimal == second.networkDecimal) ? supernet : nil
    }
    
    public static func + (lhs: IPRoute, rhs: IPRoute)->IPRoute? {
        return lhs.summarize(second: rhs)
    }
    
    // MARK: - Special address check
    
    /// Indicates wheter the whole subnet lies within bounds of private-use range.
    /// See RFC1918 for details (http://www.iana.org/go/rfc1918)
    /// To check single IP address only, please use self.ip.isPrivate
    var isPrivate: Bool {
        return overlapsDecimalRange(167772160, to: 184549375) || // 10.0.0.0/8
            overlapsDecimalRange(2886729728, to: 2887778303) || // 172.16.0.0/12
            overlapsDecimalRange(3232235520, to: 3232301055) // 192.168.0.0/16
    }
    
    /// Indicates wheter the whole subnet lies within bounds of "This host on this network" range.
    /// See RFC1122, Section 3.2.1.3 for details (http://www.iana.org/go/rfc1122)
    /// To check single IP address only, please use self.ip.isThisNetworkReserved
    var isThisNetworkReserved: Bool {
        return overlapsDecimalRange(0, to: 16777215) // 0.0.0.0/8
    }
    
    /// Indicates wheter the whole subnet lies within bounds of loopback range.
    /// See RFC1122, Section 3.2.1.3 for details (http://www.iana.org/go/rfc1122)
    /// To check single IP address only, please use self.ip.isLoopback
    var isLoopback: Bool {
        return overlapsDecimalRange(2130706432, to: 2147483647) // 127.0.0.0/8
    }
    
    /// Indicates wheter the whole subnet lies within bounds of link local range.
    /// See RFC3927 for details (http://www.iana.org/go/rfc3927)
    /// To check single IP address only, please use self.ip.isLinkLocal
    var isLinkLocal: Bool {
        return overlapsDecimalRange(2851995648, to: 2852061183) //169.254.0.0/16
    }
    
    /// Indicates wheter the whole subnet lies within bounds of shared address space.
    /// See RFC6598 for details (http://www.iana.org/go/rfc6598)
    /// To check single IP address only, please use self.ip.isSharedAddressSpace
    var isSharedAddressSpace: Bool {
        return overlapsDecimalRange(1681915904, to: 1686110207) // 100.64.0.0/10
    }
    
    /// Indicates wheter the whole subnet lies within bounds of reserved address space.
    /// See RFC1112, Section 4 for details (http://www.iana.org/go/rfc1112)
    /// To check single IP address only, please use self.ip.isReserved
    var isReserved: Bool {
        return overlapsDecimalRange(4026531840, to: 4294967295) // 240.0.0.0/4
    }
    
    /// Indicates wheter the whole subnet lies within bounds of IETF assigned address space.
    /// See RFC6890, Section 2.1 for details (http://www.iana.org/go/rfc6890)
    /// To check single IP address only, please use self.ip.isIETFAssigned
    var isIETFAssigned: Bool {
        return overlapsDecimalRange(3221225472, to: 3221225727) // 192.0.0.0/24
    }
    
    /// Indicates wheter the whole subnet lies within bounds of TEST-NET-1 address space.
    /// See RFC5737 for details (http://www.iana.org/go/rfc5737)
    /// To check single IP address only, please use self.ip.isTestNet1
    var isTestNet1: Bool {
        return overlapsDecimalRange(3221225984, to: 3221226239) // 192.0.2.0/24
    }
    
    /// Indicates wheter the whole subnet lies within bounds of TEST-NET-2 address space.
    /// See RFC5737 for details (http://www.iana.org/go/rfc5737)
    /// To check single IP address only, please use self.ip.isTestNet2
    var isTestNet2: Bool {
        return overlapsDecimalRange(3325256704, to: 3325256959) // 198.51.100.0/24
    }
    
    /// Indicates wheter the whole subnet lies within bounds of TEST-NET-2 address space.
    /// See RFC5737 for details (http://www.iana.org/go/rfc5737)
    /// To check single IP address only, please use self.ip.isTestNet3
    var isTestNet3: Bool {
        return overlapsDecimalRange(3405803776, to: 3405804031) // 203.0.113.0/24
    }
    
    /// Indicates wheter the whole subnet lies within bounds of benchmarking address space.
    /// See RFC2544 for details (http://www.iana.org/go/rfc2544)
    /// To check single IP address only, please use self.ip.isBenchmarking
    var isBenchmarking: Bool {
        return overlapsDecimalRange(3323068416, to: 3323199487) // 198.18.0.0/15
    }
    
    /// Indicates wheter the whole subnet can be globally reachable
    /// To check single IP address only, please use self.ip.isGloballyReachable
    var isGloballyReachable: Bool {
        return isPrivate || isLoopback || isReserved || isTestNet1 || isTestNet2 || isTestNet3 || isLinkLocal || isIETFAssigned || isBenchmarking || isThisNetworkReserved ||
        isSharedAddressSpace
    }
    
}

// MARK: - CustomStringConvertible

extension IPRoute: CustomStringConvertible {
    /// String representation of the IP address of the /32 subnet (i.e. "192.168.0.10") or
    /// complete CIDR notation otherwise (i.e. "192.168.0.10/24")
    var description: String {
        return ip.ipAddr.map({String($0)}).joined(separator: ".")
            .appending(prefix < 32 ? "/\(prefix)" : "")
    }
}

// MARK: - Equatable

extension IPRoute: Equatable {
    
    static func == (lhs: IPRoute, rhs: IPRoute) -> Bool {
        return (lhs.ip.ipDecimal == rhs.ip.ipDecimal) && (lhs.prefix == rhs.prefix)
    }
    
}

// MARK: - Comparable

extension IPRoute: Comparable {
    
    /// This comparision is used to sort nonoverlapping routes for summarization
    /// - Returns: routes compared by address first, network prefix next, both in ascending order
    static func < (lhs: IPRoute, rhs: IPRoute) -> Bool {
        if lhs.ip.ipDecimal != rhs.ip.ipDecimal {
            return lhs.ip.ipDecimal < rhs.ip.ipDecimal
        } else {
            return lhs.prefix < rhs.prefix
        }
    }
}

// MARK: - Hashable

extension IPRoute: Hashable {
    var hashValue: Int {
        return ip.ipDecimal.hashValue ^ prefixDecimal.hashValue
    }
}

// MARK: - IPRangeProtocol
extension IPRoute: IPRangeProtocol {
    
    var rngLow: IPAddress {
        return IPAddress(decimal: networkDecimal)
    }
    
    var rngHigh: IPAddress {
        return IPAddress(decimal: broadcastDecimal)
    }
}

//==================================================================================================

struct IPRange: IPRangeProtocol {
    
    let low: IPAddress
    let high: IPAddress
    
    var rngLow: IPAddress {
        return low
    }
    
    var rngHigh: IPAddress {
        return high
    }
    
    init?(_ lo: IPAddress, to: IPAddress) {
        guard lo < to else {
            return nil
        }
        low = lo
        high = to
    }
    
    init(_ rt: IPRoute) {
        low = IPAddress(decimal: rt.networkDecimal)
        high = IPAddress(decimal: rt.broadcastDecimal)
    }
    
    init?(_ lo: IPRoute, to: IPAddress) {
        // Check if IPRoute represents the whole subnet, not just an address within
        guard lo.prefix == 32 || lo.ip.ipDecimal == lo.networkDecimal else {
            return nil
        }
        if lo.broadcastDecimal + 1 == to.ipDecimal {
            low = IPAddress(decimal: lo.networkDecimal)
            high = to
        } else {
            return nil
        }
    }
    
    init?(_ lo: IPAddress, to: IPRoute) {
        // Check if IPRoute represents the whole subnet, not just an address within
        guard to.prefix == 32 || to.ip.ipDecimal == to.networkDecimal else {
            return nil
        }
        if lo.ipDecimal + 1 == to.networkDecimal {
            low = lo
            high = IPAddress(decimal: to.broadcastDecimal)
        } else {
            return nil
        }
    }
    
    init?(_ lo: IPRoute, to: IPRoute) {
        // Check if IPRoutes represent whole subnets, not just addresses within
        guard (to.prefix == 32 || to.ip.ipDecimal == to.networkDecimal) &&
            (lo.prefix == 32 || lo.ip.ipDecimal == lo.networkDecimal) else {
                return nil
        }
        if lo.broadcastDecimal + 1 == to.networkDecimal {
            low = IPAddress(decimal: lo.networkDecimal)
            high = IPAddress(decimal: to.broadcastDecimal)
        } else {
            return nil
        }
    }
    
    init?(_ s: String) {
        let parts = s.components(separatedBy: "-")
        if parts.count == 2,
            let l = IPAddress(parts[0]),
            let h = IPAddress(parts[1]), l < h {
            low = l
            high = h
        } else if parts.count == 1, let rt = IPRoute(parts[0]) {
            low = IPAddress(decimal: rt.networkDecimal)
            high = IPAddress(decimal: rt.broadcastDecimal)
        } else {
            return nil
        }
    }
    
    static func + (lhs: IPRange, rhs: IPRange)->IPRange? {
        guard lhs.high.ipDecimal + 1 == rhs.low.ipDecimal else { return nil }
        return IPRange(lhs.low, to: rhs.high)
    }
    
    // this should be network wildcard:
    private var mayBeWildcard: UInt32 {
        return low.ipDecimal ^ high.ipDecimal
    }
    
    var subnetConvertable: Bool {
        // test wildcard first:
        var wc = mayBeWildcard
        while (wc > 0) {
            if wc % 2 != 1 {
                return false
            }
            wc >>= 1
        }
        
        // wildcard OR low == network's last address
        return high.ipDecimal == (low.ipDecimal | mayBeWildcard)
    }
    
    var ipAddressCount: Int {
        return Int(high.ipDecimal - low.ipDecimal) + 1
    }
    
    // Subnetting and supernetting
    
    static func overlaps(lhs: IPRange, rhs: IPRange)->Bool {
        return (lhs.low <= rhs.low && lhs.high >= rhs.low) ||
            (rhs.low <= lhs.low && rhs.high >= lhs.low)
    }
}

// MARK: - Custom string convertable and other descriptors
extension IPRange: CustomStringConvertible {
    
    var description: String {
        return "\(low)-\(high)"
    }
    
    var subnetDescription: String? {
        guard subnetConvertable else { return nil }
        var wc = mayBeWildcard
        var prefix = 32
        while (wc > 0) {
            wc = wc >> 1
            prefix -= 1
        }
        
        var bigEndian = low.ipDecimal.bigEndian
        let count = MemoryLayout<UInt32>.size
        let bytePtr = withUnsafePointer(to: &bigEndian) {
            $0.withMemoryRebound(to: UInt8.self, capacity: count) {
                UnsafeBufferPointer(start: $0, count: count)
            }
        }
        return Array(bytePtr).map({String($0)}).joined(separator: ".").appending("\(prefix < 32 ? "/\(prefix)" : "")")
    }
    
    var subnetOrRangeDescription: String {
        return subnetDescription ?? description
    }
    
}

// MARK: - Equatable

extension IPRange: Equatable {
    static func == (lhs: IPRange, rhs: IPRange) -> Bool {
        return lhs.low == rhs.low && lhs.high == rhs.high
    }
}

// Sorting functions
extension IPRange: Comparable {
    
    // Sort by low ip by default
    static func < (lhs: IPRange, rhs: IPRange) -> Bool {
        return lhs.low < rhs.low
    }
    
    static func highIpLessThanOther(lhs: IPRange, rhs: IPRange) -> Bool {
        return lhs.low < rhs.low
    }
}

//==================================================================================================

protocol IPRangeProtocol: Equatable {
    var rngLow: IPAddress { get }
    var rngHigh: IPAddress { get }
}

//==================================================================================================

struct IPCleanup {
    
    static func removeDuplicateSubnets(ips: [IPRoute])->[IPRoute] {
        var output: [IPRoute] = ips.sorted()
        var removed = 0
        var i = 1
        var count = output.count
        while (i < count) {
            if output[i - 1].subnetIncludes(second: output[i]) {
                output.remove(at: i)
                removed += 1
                count -= 1
            } else {
                i += 1
            }
        }
        let addrRemoved = ips.map({$0.ipAddressCount}).reduce(0, +) - output.map({$0.ipAddressCount}).reduce(0, +)
        print("\(Date()) | \(removed) subnet route records of \(addrRemoved) IP addresses removed because they were part of enlisted supernets")
        return output
    }
    
    static func removeNonGlobalSubnets(ips: [IPRoute])->[IPRoute] {
        let output = ips.filter({!$0.isGloballyReachable})
        print("\(Date()) | \(ips.count - output.count) records removed beacause of the non-global status")
        return output
    }
    
    static func collapseToSubnets(ips: [IPRoute], verbose: Bool = false)->[IPRoute] {
        guard ips.count > 0 else { return [] }
        var output = ips.sorted()
        var i = 1
        var removed = 0
        var count = output.count
        while i < count {
            if let supernet = output[i-1].summarize(second: output[i]) {
                if verbose {
                    print(String(repeating: " ", count: Int(32 - supernet.prefix)), "\(output[i-1]) + \(output[i]) = \(supernet)")
                }
                output[i - 1] = supernet
                output.remove(at: i)
                count -= 1
                removed += 1
                if i - 1 > 0 { i -= 1 }
            } else {
                i += 1
            }
        }
        print("\(Date()) | \(removed) records removed due to summarization")
        return output
    }
    
    static func collapseToRanges(routes: [IPRoute])->[IPRange] {
        guard routes.count > 0 else { return [] }
        var ranges = routes.sorted().map({IPRange($0)})
        var i = 1
        var removed = 0
        var count = ranges.count
        while i < count {
            if let superrange = ranges[i-1] + ranges[i] {
                ranges[i - 1] = superrange
                ranges.remove(at: i)
                count -= 1
                removed += 1
                if i - 1 > 0 {
                    // Step back to test wheter previous element can be merged with current
                    i -= 1
                }
            } else {
                i += 1
            }
        }
        print("\(Date()) | \(removed) records removed due to summarization")
        return ranges
    }
    
}

