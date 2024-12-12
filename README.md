# RawHttpServer

This is a [raw socket HTTP server](https://squidarth.com/networking/systems/rc/2018/05/28/using-raw-sockets.html), which means it's responsible for handling the three-way handshake and constructing packets. Memory is managed using [arenas](https://www.rfleury.com/p/enter-the-arena-talk).

## References:
- [TCP RFC](https://datatracker.ietf.org/doc/html/rfc9293)
- [HTTP RFC](https://datatracker.ietf.org/doc/html/rfc2616#section-4.2)