# Dataset Dictionary

The canonical metadata and label fields are defined in
[`dataset_schema.md`](dataset_schema.md). Model-eligible feature definitions are
not duplicated or renamed here: the authoritative dictionary is
[`feature_dictionary.md`](feature_dictionary.md) and the machine-readable
contract is `artifacts/feature_schema.json`.

## Ordered feature vector

The order is fixed at 43 fields:

1. `total_packets`
2. `total_bytes`
3. `forward_packets`
4. `backward_packets`
5. `forward_bytes`
6. `backward_bytes`
7. `packets_per_second`
8. `bytes_per_second`
9. `forward_backward_packet_ratio`
10. `forward_backward_byte_ratio`
11. `mean_packet_size`
12. `std_packet_size`
13. `min_packet_size`
14. `max_packet_size`
15. `median_packet_size`
16. `packet_size_q25`
17. `packet_size_q75`
18. `forward_mean_packet_size`
19. `backward_mean_packet_size`
20. `flow_duration`
21. `mean_inter_arrival_time`
22. `std_inter_arrival_time`
23. `min_inter_arrival_time`
24. `max_inter_arrival_time`
25. `median_inter_arrival_time`
26. `iat_q25`
27. `iat_q75`
28. `forward_mean_iat`
29. `backward_mean_iat`
30. `syn_count`
31. `ack_count`
32. `fin_count`
33. `rst_count`
34. `psh_count`
35. `urg_count`
36. `syn_ratio`
37. `rst_ratio`
38. `ack_ratio`
39. `completed_handshake_indicator`
40. `asymmetry_score`
41. `connection_burst_score`
42. `periodicity_score`
43. `failed_connection_indicator`

Metadata and labels are deliberately absent from this list. Phase 4 does not
drop constant features, resample classes, or modify Phase 3 semantics.
