Zeroconf Service Discovery
==========================
[![GoDoc](https://godoc.org/github.com/betamos/zeroconf?status.svg)](https://godoc.org/github.com/betamos/zeroconf)
[![Tests](https://github.com/betamos/zeroconf/actions/workflows/go-test.yml/badge.svg)](https://github.com/libp2p/zeroconf/actions/workflows/go-test.yml)

Zeroconf is a pure Golang library for discovering and publishing services on the local network.

It is tested on Windows, macOS and Linux and is compatible with [Avahi](http://avahi.org/),
[Bonjour](https://developer.apple.com/bonjour/), etc. It implements:

- [RFC 6762](https://tools.ietf.org/html/rfc6762): Multicast DNS (mDNS)
- [RFC 6763](https://tools.ietf.org/html/rfc6763): DNS Service Discovery (DNS-SD)

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
    Browse(chat, func(e zeroconf.Event) {
        // Prints e.g. `[+] Bryan`, but this would be a good time to connect to the peer!
        log.Println(e.Op, e.Name)
    })
    .Open()
if err != nil {
    return err
}
defer client.Close() // Don't forget to close, to notify others that we're going away
```

## CLI

The package contains a CLI which can both browse and publish:

```bash
# Browse and publish at the same time (run on two different machines)
go run ./cmd -b -p "Computer A"
go run ./cmd -b -p "Computer B"

# Or why not find some Apple devices?
go run ./cmd -b -type _rdlink._tcp
```

You should see services coming and going, like so:

```
01:23:45 [+] Someone's iPhone ...
01:23:47 [+] Some Macbook ...
01:26:45 [-] Someone's iPhone ...
```

## Features

* [x] Publish and browse on the same UDP port
* [x] Monitors for updates, expiry and unannouncements of services
* [x] Handles IPv4 and IPv6 on multiple network interfaces
* [x] Minimal network traffic
* [x] Hot-reload after network changes or sleeping (see below)
* [x] Uses modern Go 1.21 with `slog`, `netip`, etc

## Hot-reloading

Some devices, like laptops, move around a lot. Whenever a device connects to a new network,
or wakes up after sleep, the zeroconf client needs to be aware of these changes for both
browsing and publishing to work correctly:

```go
// Reloads network interfaces and resets periodic timers
client.Reload()
```

Monitoring for changes is out of scope for this project. You could use a ticker and reload
every N minutes.

## Missing features

- **Conflict resolution** is not implemented, so it's important to pick a unique service name to
  avoid name collisions. If you don't have a unique persistent identifier, you could add randomized
  suffix, e.g "Jennifer [3298]".
- **One-shot queries** (lookup) is currently not supported. As a workaround, you can browse
  and filter out the instance yourself.
- **Meta-queries** are also not supported.

## About

This project is a near-complete rewrite by Didrik Nordström in 2023.
However, archeologists will find a long lineage:

- [hashicorp/mdns](https://github.com/hashicorp/mdns)
- [oleksandr/bonjour](https://github.com/oleksandr/bonjour)
- [grandcat/zeroconf](https://github.com/grandcat/zeroconf)
- [libp2p/zeroconf](https://github.com/libp2p/zeroconf)
- [betamos/zeroconf](https://github.com/betamos/zeroconf) <- You are here
