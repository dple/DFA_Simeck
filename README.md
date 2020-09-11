# Differential Fault Analysis (DFA) against SIMECK family of lightweight block ciphers
---
## SIMECK ciphers
SIMECK family of lightweight block ciphers was introduced by researchers from University of Waterloo [1]. This is a family of lightweight block ciphers based upon a balanced Feistel structure that combines the good design principles of the SIMON and SPECK block ciphers [2]. Specifically, SIMECK  consists of three members with block sizes of 32, 48 and 64 and the corresponding key sizes are 64, 96 and 128, respectively. As demonstrated in [1], SIMECK allows a smaller and more efficient hardware implementation in comparison to  SIMON. Due to its nice property in efficiency, SIMECK has been significantly analyzed since its publication.

## DFA attacks 
More detailed description of the attacks will be appeared soon.

## Simulation
This code project provides a simulation of DFA attack against all three ciphers in SIMECK family. 

## Results
A detail of simulation will be provided soon.

---
# References

[1] **The Simeck Family of Lightweight Block Ciphers**, by Gangqiang Yang, Bo Zhu, Valentin Suder, Mark D. Aagaard, and Guang Gong, CHES 2015. https://eprint.iacr.org/2015/612

[2] **SIMON and SPECK: Block Ciphers for the Internet of Things**, Ray Beaulieu and Douglas Shors and Jason Smith and Stefan Treatman-Clark and Bryan Weeks and Louis Wingers. https://eprint.iacr.org/2015/585
