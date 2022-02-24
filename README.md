# Differential Fault Analysis (DFA) against SIMECK family of lightweight block ciphers
---
## SIMECK ciphers
SIMECK family of lightweight block ciphers was introduced by researchers from University of Waterloo [1]. This is a family of lightweight block ciphers based upon a balanced Feistel structure that combines the good design principles of the SIMON and SPECK block ciphers [2]. Specifically, SIMECK  consists of three members with block sizes of 32, 48 and 64 and the corresponding key sizes are 64, 96 and 128, respectively. As demonstrated in [1], SIMECK allows a smaller and more efficient hardware implementation in comparison to  SIMON. Due to its nice property in efficiency, SIMECK has been significantly analyzed since its publication.

## DFA attacks 
More detailed description of the attacks will be appeared soon.

## Simulation
This code project provides a simulation of DFA attack against all three ciphers in SIMECK family. There are three source code files coressponding to the proposed attacks to three members of SIMECK family of lightweight block ciphers. Each attack will recover not only the last round key, but also the full master key. 

The simulation attacks will run 10,000 times and output the average number of faults injected to recover the aforementioned keys. 

## How to use?
### Download

*git clone https://github.com/dple/DFA_Simeck.git*

### Compile
We provide a Makefile to compile source files. It is thus easy to compile all attacks at once with the following command in the same source folder:

  *make*


After compiling, you will have three executable files: FA_SIMECK32, FA_SIMECK48, and FA_SIMECK64, each for one member of SIMECK. 


## Results
For each cipher member, we carried out 10,000 simulation attacks and report the average number of faulty ciphers required to recover the last round key ![formula](https://render.githubusercontent.com/render/math?math=$K^{T - 1}) and the whole master key (corresponding to the last 4 round keys $K^{T - 1}$, $K^{T - 2}$, $K^{T - 3}$, and $K^{T - 4}$).


---
# References

[1] **Improved fault analysis on SIMECK ciphers**, by Duc-Phong Le, Rongxing Lu and Ali A. Ghorbani, Journal of Cryptographic Engineering, 2021, https://link.springer.com/article/10.1007/s13389-021-00263-w 

[2] **The Simeck Family of Lightweight Block Ciphers**, by Gangqiang Yang, Bo Zhu, Valentin Suder, Mark D. Aagaard, and Guang Gong, CHES 2015. https://eprint.iacr.org/2015/612

[3] **SIMON and SPECK: Block Ciphers for the Internet of Things**, Ray Beaulieu and Douglas Shors and Jason Smith and Stefan Treatman-Clark and Bryan Weeks and Louis Wingers. https://eprint.iacr.org/2015/585
