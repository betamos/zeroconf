# Zeroconf Service Discovery

[![GoDoc](https://godoc.org/github.com/betamos/zeroconf?status.svg)](https://godoc.org/github.com/betamos/zeroconf)
[![Tests](https://github.com/betamos/zeroconf/actions/workflows/go-test.yml/badge.svg)](https://github.com/betamos/zeroconf/actions/workflows/go-test.yml)

Zeroconf is a pure Golang library for discovering and publishing services on the local network.

It is tested on Windows, macOS and Linux and is compatible with [Avahi](http://avahi.org/),
[Bonjour](https://developer.apple.com/bonjour/), etc. It implements:

-   [RFC 6762](https://tools.ietf.org/html/rfc6762): Multicast DNS (mDNS)
-   [RFC 6763](https://tools.ietf.org/html/rfc6763): DNS Service Discovery (DNS-SD)

## Features

-   [x] Monitors updates, expiry and unannouncements of services
-   [x] Publish and browse on the same socket, with minimal network traffic
-   [x] Advertises a small set of IPs per network interface [1]
-   [x] Option for more reliable addrs based on packet source (instead of self-reported)
-   [x] Hot-reload after network changes or sleeping (see below)
-   [x] Uses modern Go 1.21 with `slog`, `netip`, etc

[1]: Some other clients advertise all IPs to every interface, which results in many
redundant and unreachable addresses. This library advertises at most 3 IPs per network interface
(IPv4, IPv6 link-local and IPv6 global). When browsing, you'll see the union of all _reachable_
addresses from all interfaces.

## Usage

First, let's install the library:

```bash
$ go get -u github.com/betamos/zeroconf
```

Then, let's import the library and define a service type:

```go
import "github.com/betamos/zeroconf"

var chat = zeroconf.NewType("_chat._tcp")
```

Now, let's announce our own presence and find others we can chat with:

```go
// This is the chat service running on this machine
self := zeroconf.NewService(chat, "Jennifer", 8080)

client, err := zeroconf.New().
    Publish(self).
    Browse(func(e zeroconf.Event) {
        // Prints e.g. `[+] Bryan`, but this would be a good time to connect to the peer!
        log.Println(e.Op, e.Name)
    }, chat).
    Open()
if err != nil {
    return err
}
defer client.Close() // Don't forget to close, to notify others that we're going away
```

Devices like laptops move around a lot. When networks change or a device wakes up from sleep,
zeroconf needs to be notified:

```go
// Reloads network interfaces and resets periodic timers
client.Reload()
```

Monitoring for changes is out of scope for this project. You could use a ticker and reload
every N minutes.

## CLI

This package also includes a CLI:

```bash
# Lets find some Apple devices
go run ./cmd -b -type _rdlink._tcp
```

To demonstrate the resilience to network changes, run this on two separate devices:

```bash
# Browse and publish at the same time, with frequent reloading and short expiry
go run ./cmd -b -p "Machine A" -reload 10 -expiry 10
go run ./cmd -b -p "Machine B" -reload 10 -expiry 10
```

Now, try turning on and off Wifi, suspending, etc and watch out for changes.
The state of the device should be reflected within seconds:

```
11:26:45 [+] Machine B [192.168.1.12, ...]
11:26:52 [~] Machine B [192.168.1.12, 192.168.1.24, ...]
11:27:02 [-] Machine B []
```

An update (note the `~`) means that something changed with the service, such as its IPs.

## Missing features

-   **Conflict resolution** is not implemented, so it's important to pick a unique service name to
    avoid name collisions. If you don't have a unique persistent identifier, you could add randomized
    suffix, e.g "Jennifer [3298]".
-   **One-shot queries** (lookup) is currently not supported. As a workaround, you can browse
    and filter out the instance yourself.
-   **Meta-queries** are also not supported (but we still respond to them correctly).
-   **Updating services**, such as their TXT records, is not supported. Perhaps it should be?

## About

This project is a near-complete rewrite by Didrik Nordström in 2023.
However, archeologists will find a noble lineage of honorable predecessors:

-   [hashicorp/mdns](https://github.com/hashicorp/mdns)
-   [oleksandr/bonjour](https://github.com/oleksandr/bonjour)
-   [grandcat/zeroconf](https://github.com/grandcat/zeroconf)
-   [libp2p/zeroconf](https://github.com/libp2p/zeroconf)
-   [betamos/zeroconf](https://github.com/betamos/zeroconf) ← You are here
