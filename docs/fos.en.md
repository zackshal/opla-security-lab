# Assessment materials

[Русский](fos.md) · **English**

I prepared these materials for the laboratory: assessment concerns both reproducible commands and the reasoning behind each filtering decision. The tasks below are addressed to the student.

## 1 Practical exercises

1. **Basic.** Deploy the lab, check isolation and HTTP. Send the same bounded workload without and with XDP. Submit commands, counters and independent-client HTTP results. **Criterion:** reproducibility and a correct interpretation of pass/drop.
2. **Parameters.** Compare `THRESHOLD=100` and `THRESHOLD=200` under the same load. Identify the XDP mode and new counter epochs after reload. **Criterion:** a defensible conclusion without confusing SYN packets with completed TCP connections.
3. **Telemetry failure.** Stop the collector for more than 60 seconds while XDP remains active. Find the missing-data event, restore collection and distinguish this state from `loaded=0` and `drop.rate=0`. **Criterion:** do not present missing measurements as zero traffic.
4. **Extension.** Modify the limiter so that it applies only to TCP destination port 80. Preserve bounds checks and synchronization; add packet tests for ports 80 and 22. Compare SSH and HTTP. **Criterion:** source changes, tests and a discussion of policy boundaries.
5. **Application layer.** Run the HTTP keep-alive workload after enabling `limit_req`. Correlate 200/429 responses, `http.limited` and independent client availability; explain the difference from SYN rate limiting. **Criterion:** real HTTP evidence without unsupported SQLi/XSS protection claims.

## 2 Self-check questions

1. Which packets constitute a TCP handshake, and when does SYN-RECV occur?
2. Why does a high SYN rate alone not prove malicious intent?
3. Where do native and generic XDP run?
4. What does the map spin lock protect, and why may an ordinary `++` be insufficient?
5. Why is a fixed-window count unsuitable for cumulative traffic-rate calculations?
6. How do users behind the same NAT share a source-IP limit?
7. What happens to new clients when the source map is full?
8. What evidence establishes that a service remained available?
9. Why can one SYN precede several HTTP requests?
10. How does HTTP 429 differ from a TCP timeout and XDP_DROP?

## 3 Multiple-choice test

Choose one answer for each question. The answer key is provided to the instructor separately.

1. Which packet is counted by the main SYN counter?
   A. Every TCP packet. B. SYN=1, ACK=0. C. SYN=1, ACK=1. D. Every UDP packet.
2. What is returned for the 101st SYN from one IP in an unchanged window with `THRESHOLD=100`?
   A. XDP_PASS. B. XDP_REDIRECT. C. XDP_DROP. D. XDP_TX.
3. How is the first packet after a window expires counted?
   A. It starts with count=1. B. It is ignored. C. It retains the old count. D. It is always dropped.
4. Which statement about generic XDP is true?
   A. It runs only in a browser. B. It is always faster than native. C. It does not use the kernel. D. It operates after an skb has been created.
5. What is suitable for calculating a rate?
   A. Interface-name length. B. The difference between cumulative counters and elapsed time. C. Only the last window count. D. Source-code line count.
6. What does a lack of new collector data mean?
   A. No packets arrived. B. XDP is definitely unloaded. C. State is unknown until telemetry is checked. D. All packets were blocked.
7. What can happen to clients behind one NAT?
   A. They share a source-IP budget. B. Each automatically gets a separate budget. C. NAT disables TCP. D. They cannot use HTTP.
8. What happens to a new source IP if insertion into `syn_windows` fails?
   A. The entire program is deleted. B. The SYN always passes. C. The IPv4 address changes. D. The SYN is dropped and `map_full` increases.
9. Where should traffic potentially dropped by native XDP be captured?
   A. Only in HTTP access.log. B. At attacker or a suitable bridge capture point. C. Only after XDP on victim. D. In README.
10. How does the current IPv4 limiter handle an IPv6 SYN?
    A. It applies the IPv4 limit. B. It always increments `syn`. C. It passes an unsupported protocol. D. It selects another threshold.
11. Why test HTTP separately from SYN flooding?
    A. HTTP does not use TCP. B. One TCP connection can carry several requests. C. Every HTTP request creates 1,000 SYNs. D. XDP always decrypts TLS.
12. What does `XDP attached=1` mean?
    A. Every possible sensor is connected. B. An XDP program is attached to the monitored interface. C. Every packet is dropped. D. HTTP is externally reachable.
