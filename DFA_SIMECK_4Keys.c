#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "simeck.h"

void printbinary(uint16_t x);
uint16_t flip_bip(uint16_t x, uint8_t position, uint8_t word_size);
int matchPattern(uint16_t data);
uint8_t getFaultPosition32(uint16_t delta);
uint8_t getFaultPosition48(uint32_t delta);
uint8_t getFaultPosition64(uint32_t delta);
int satisfatory(uint8_t *array, int size);
int rightPosition(int pos, int wordsize);
void delay(int number_of_seconds);

int main(void) {

    /* Plaintext and Key used to encrypt */
	uint16_t text32[] = {
        0x6877,
        0x6565,
    };
    const uint16_t key64[] = {
        0x0100,
        0x0908,
        0x1110,
        0x1918,
    };
    uint32_t text48[] = {
        0x20646e,
        0x726963,
    };
    const uint32_t key96[] = {
        0x020100,
        0x0a0908,
        0x121110,
        0x1a1918,
    };
    
    uint32_t text64[] = {
        0x20646e75,
        0x656b696c,
    };
    const uint32_t key128[] = {
        0x03020100,
        0x0b0a0908,
        0x13121110,
        0x1b1a1918,
    };

    const int NUM_ROUNDS32 = 32;
    const int NUM_ROUNDS48 = 36;
    const int NUM_ROUNDS64 = 44;
	const int8_t WORD_SIZE32 = 16;    
    const int8_t WORD_SIZE48 = 24;    
    const int8_t WORD_SIZE64 = 32;    

    /* Assign values for a cipher computed */
    int NUM_ROUNDS = NUM_ROUNDS32;
    int WORD_SIZE = WORD_SIZE32;   
	const uint16_t *master_key = key64;
    const uint16_t *plaintext = text32;

    uint8_t stateKeys[4][WORD_SIZE];        // Record if a key bit recovered from K(T - 1) to K(T - 4): 1 - recovered, 0 - not recovered
    uint8_t stateDelta[2][WORD_SIZE];       // Indicate if bits of Delta(T - 3), Delta(T - 4) are known: 1 -  known, 0 - unknown
    int idx;
    uint16_t ciphertext[2];

    uint16_t keys[4] = {
        master_key[0],
        master_key[1],
        master_key[2],
        master_key[3],
    };
    uint16_t tempkeys[4]; 

	ciphertext[0] = plaintext[0];
    ciphertext[1] = plaintext[1];
    uint16_t temp;

    uint16_t constant32 = 0xFFFC;
    uint32_t sequence32 = 0x9A42BB1F;	
	int8_t pos;
	int8_t faultpos;

	srand(time(NULL));

    for (idx = 0; idx < NUM_ROUNDS - 5; idx++) {
        ROUND32(
                keys[0],
                ciphertext[1],
                ciphertext[0],
                temp
        );

        constant32 &= 0xFFFC;
        constant32 |= sequence32 & 1;
        sequence32 >>= 1;
        ROUND32(
                constant32,
                keys[1],
                keys[0],
                temp
        );

        // rotate the LFSR of keys
        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;
    }

		
	int n_faults = 0;
    int sum_faults = 0;
    uint16_t correctcipher[2];  // for encryption correct text
    uint16_t faultycipher[2];   // for encryption faulty text

    uint16_t correcttext[6]; //uint16_t correcttext[6][2]; // imm     
	uint16_t faultytext[6]; //uint16_t faultytext[6][2];
    uint16_t delta[6];   //uint16_t delta[6][2];
    int temppos;
    int i, j;

    for (idx = 0; idx < 10000; idx++)
    {           
        n_faults = 0; // Initialize the number of bits injected

        /* Initialize the state array, indicating that all bits not yet recovered */
        for (i = 0; i < 4; i++)
            for (j = 0; j < WORD_SIZE; j++)
                stateKeys[i][j] = 0;
            
                    
        while (!satisfatory((uint8_t *)stateKeys, WORD_SIZE))
        {
            n_faults +=1;

            /* Initialize the array of Delta(T - 3), indicating that all bits not yet known */
            for (i = 0; i < 2; i++)
                for (j = 0; j < WORD_SIZE; j++)            
                    stateDelta[i][j] = 0;
            
            for (i = 0; i < 4; i++)
                tempkeys[i] = keys[i];
            
            // Inject a fault into the input at the round T - 5
            pos = rand() % WORD_SIZE;
            // correcttext and faultytext will be used to compute input differences from round T - 5 to T
            correcttext[0] = ciphertext[1];
            faultytext[0] = flip_bip(ciphertext[1], pos, WORD_SIZE); //faultytext[0][0] = ciphertext[0];
            
            // Set immediate correct and faulty ciphertext as ones at round T - 5
            correctcipher[0] = ciphertext[0];
            correctcipher[1] = ciphertext[1]; 
            faultycipher[0] = ciphertext[0];            
            faultycipher[1] = faultytext[0];        //printf("Faulty ciphertext at the roun 27 is: %04x %04x\n", faultycipher[1], faultycipher[0]);

            // Initialize input differences
            delta[0] = faultytext[0] ^ correcttext[0]; //  delta[0][0] = faultytext[0][0] ^ correcttext[0][0]; //printf("fault at: %d\n", pos); printbinary(delta[0]); printf("\n");

            for (i = 0; i < 5; i++) {	
                ROUND32(
                        tempkeys[0],
                        correctcipher[1],
                        correctcipher[0],
                        temp
                );

                // Faulty encryption
                ROUND32(
                        tempkeys[0],
                        faultycipher[1],
                        faultycipher[0],
                        temp
                );

                constant32 &= 0xFFFC;
                constant32 |= sequence32 & 1;
                sequence32 >>= 1;
                ROUND32(
                        constant32,
                        tempkeys[1],
                        tempkeys[0],
                        temp
                );
                
                // rotate the LFSR of keys
                temp = tempkeys[1];
                tempkeys[1] = tempkeys[2];
                tempkeys[2] = tempkeys[3];
                tempkeys[3] = temp;
                
                correcttext[i + 1] = correctcipher[1]; //correcttext[idx + 1] = correctcipher[0];
                faultytext[i + 1] = faultycipher[1];   // faultytext[idx + 1][0] = faulty[0];            
                delta[i + 1] = faultytext[i + 1] ^ correcttext[i + 1]; //delta[idx + 1][0] = faultytext[idx + 1][0] ^ correcttext[idx + 1][0];            
            }     
            
            /* Get the fault position by matching pattern of delta T - 2 */
            faultpos = getFaultPosition32(delta[3]);		

            /* Determine known bits of Delta(T - 3) and Delta(T - 4) from the fault position recovered */
            for (j = 2; j < 5; j++){
                stateDelta[0][rightPosition(faultpos + j, WORD_SIZE)] = 1;      // stateDelta[0] is Delta(T - 3)
                stateDelta[1][rightPosition(faultpos + j, WORD_SIZE)] = 1;      // stateDelta[1] is Delta(T - 4)
            }
            stateDelta[1][rightPosition(faultpos + 1, WORD_SIZE)] = 1;

            for (j = 7; j < 10; j++){
                stateDelta[0][rightPosition(faultpos + j, WORD_SIZE)] = 1;
                stateDelta[1][rightPosition(faultpos + j, WORD_SIZE)] = 1;      
            }
            stateDelta[1][rightPosition(faultpos + 6, WORD_SIZE)] = 1;      // stateDelta[1] is Delta(T - 4)
            
            for (j = 11; j < WORD_SIZE; j++){
                stateDelta[0][rightPosition(faultpos + j, WORD_SIZE)] = 1;
                stateDelta[1][rightPosition(faultpos + j, WORD_SIZE)] = 1;      // stateDelta[1] is Delta(T - 4)
            }
            stateDelta[1][rightPosition(faultpos + 10, WORD_SIZE)] = 1;      
            /*
            printf("Fault position is: %d \n", faultpos);
            for (j = 0; j < WORD_SIZE; j++)
            {
                printf(" %d ", stateDelta[1][j]);
            }
            printf("\n");*/
            
            // Recover key bits from linear expressions, Step 4.1
            stateKeys[0][rightPosition(faultpos - 2, WORD_SIZE)] = 1;           // stateKeys[0] means K(T - 1)
            stateKeys[0][rightPosition(faultpos + 8, WORD_SIZE)] = 1;       
            stateKeys[1][rightPosition(faultpos - 3, WORD_SIZE)] = 1;           // stateKeys[0] means K(T - 2)
            stateKeys[1][rightPosition(faultpos + 7, WORD_SIZE)] = 1;       
            stateKeys[2][rightPosition(faultpos - 4, WORD_SIZE)] = 1;           // stateKeys[0] means K(T - 3)
            stateKeys[2][rightPosition(faultpos + 6, WORD_SIZE)] = 1;       
            stateKeys[3][rightPosition(faultpos - 5, WORD_SIZE)] = 1;           // stateKeys[0] means K(T - 4)
            stateKeys[3][rightPosition(faultpos + 5, WORD_SIZE)] = 1;       
            // Recover bits from Step 4.2
            for (i = 0; i < WORD_SIZE; i++)
            {
                // Recover K(T - 1)
                if (GETBIT(delta[3], i)  == 1){           // Delta(T - 2)
                    if ((GETBIT(delta[3], rightPosition(i - 5, WORD_SIZE))  == 0) && (stateDelta[0][i] == 1))
                        stateKeys[0][rightPosition(i - 5, WORD_SIZE)] = 1;              
                }
                if (GETBIT(delta[3], i)  == 1){
                    if ((GETBIT(delta[3], rightPosition(i + 5, WORD_SIZE))  == 0) && (stateDelta[0][rightPosition(i + 5, WORD_SIZE)] == 1))
                        stateKeys[0][rightPosition(i + 5, WORD_SIZE)] = 1;              
                }
                // Recover K(T - 2)
                if (GETBIT(delta[2], i)  == 1){           // Delta(T - 3)
                    if ((GETBIT(delta[2], rightPosition(i - 5, WORD_SIZE))  == 0) && (stateDelta[1][i] == 1))
                        stateKeys[1][rightPosition(i - 5, WORD_SIZE)] = 1;              
                }
                if (GETBIT(delta[2], i)  == 1){
                    if ((GETBIT(delta[2], rightPosition(i + 5, WORD_SIZE))  == 0) && (stateDelta[1][rightPosition(i + 5, WORD_SIZE)] == 1))
                        stateKeys[0][rightPosition(i + 5, WORD_SIZE)] = 1;              
                }
                // Recover K(T - 3)
                if ((GETBIT(delta[1], i)  == 1) && (GETBIT(delta[1], rightPosition(i - 5, WORD_SIZE))  == 0))            // Delta(T - 4)                    
                        stateKeys[2][rightPosition(i - 5, WORD_SIZE)] = 1;                              
                if ((GETBIT(delta[2], i)  == 1) && (GETBIT(delta[2], rightPosition(i + 5, WORD_SIZE))  == 0))
                        stateKeys[0][rightPosition(i + 5, WORD_SIZE)] = 1;              
            }   
        } 
        printf("No of faults to recover master key: %d \n", n_faults);
        sum_faults += n_faults;         //printf("Sum fauts is: %d\n", sum_faults);

        //delay(1);        // Delay to refresh a new random seed
    }
    printf("Simeck32/64 %04x %04x\n", correctcipher[1], correctcipher[0]);            
    printf("Average number of faults injected: %f\n", (double)sum_faults/10000);
    

    //printf("Faulty ciphertext Simeck32/64 %04x %04x\n", faultytext[5][1], faultytext[5][0]);
    //printf("Final differences %04x %04x\n", correcttext[5][1] ^ faultytext[5][1], correcttext[5][0]^ faultytext[5][0]);
    //for(idx = 0; idx < 4; idx++) {
    //    printf("Input difference at round %d, %04x %04x\n", NUM_ROUNDS32 - 5 + idx, delta[idx][1], delta[idx][0]);
    //    printbinary(delta[idx][1]); printf("\n\n"); //printbinary(delta[idx][0]); printf("\n\n");
    //}


}

void delay(int number_of_seconds) 
{ 
    // Converting time into clock cycles 
    int clock_cycles = CLOCKS_PER_SEC * number_of_seconds; 
      
    clock_t start_time = clock();       
    while (clock() < start_time + clock_cycles) 
        ; 
} 

int rightPosition(int pos, int wordsize) {    
    if (pos < 0){
        return wordsize + pos;
    }
    else {
        if (pos > wordsize - 1)
        {
            return pos - wordsize;
        }
        else
        {
            return pos;
        }
    }
}

int satisfatory(uint8_t *array, int size) {
    
    for (size_t i = 0; i < 4; i++)
    {
        for (size_t j = 0; j < size; j++)
        {            
            if (*((array + i*size) + j) == 0)
                return 0;            
        }        
    }
    return 1;
}

/***
 * Print an uint16_t in binary representation
 */
void printbinary(uint16_t x) {    
    for (int i = 0; i < 16; i++) {
        printf("%d ", (x & 0x8000) >> 15);
        x <<= 1;
    }    
}

/***
 * Flip a bit at the given postion
 * Input: given a correct input and a fault position
 * Output: faulty input 
 */
uint16_t flip_bip(uint16_t x, uint8_t position, uint8_t word_size) {
	uint16_t y;
	uint16_t temp;
	temp = x >> position;
	if (temp % 2 == 1) temp -= 1; 
	else temp += 1; 	
	y = temp << position;
	temp = x << word_size - position;
	temp = temp >> word_size - position;
	y = y | temp;
	return y;
}

/***
 * Find the pattern "10***00**000" in the input differential Delta(T - 2)
 *
 * Input: Input differences at the round T - 2
 * Output: Yes or No
*/
int matchPattern(uint16_t data) {	    
	int idx;	    
	data = data >> 1;
	
	if (data % 2 != 0) 
		return 0;		
	data = data >> 4;
	
	for(idx = 0; idx < 2; idx++) {
		if (data % 2 != 0) 
			return 0;		
		data = data >> 1;	
	}

	data = data >> 2; 
	
	for(idx = 0; idx < 3; idx++) {
		if (data % 2 != 0) 
			return 0;		
		data = data >> 1;	
	}
	return 1;
}

/***
 * Find the fault position at the round T - 5
 * 
 * Input:  Given the input differences of the round T - 2
 * Output: the fault position at the round T - 5
 */
uint8_t getFaultPosition32(uint16_t delta) {
    uint8_t ret = 0;
    uint16_t temp = delta;
	//printf("Input differences are: ");
	//printbinary(delta); printf("\n");
    
	while(ret < 16) {
		// Find the first "1" in the input differences	
		while (temp % 2 == 0) {
			ret++;			
			temp = RROT16((temp), 1);						
		}
		
		// Compare to the pattern
		if (matchPattern(temp) == 1)
			return (ret - 3 > 0? (ret - 3): 13 + ret);
		else {
			ret++;
			temp = RROT16(temp, 1);	
		}
	}		
    return ret; 
}

uint8_t getFaultPosition48(uint32_t delta) {
    uint8_t ret = 0;
    uint32_t temp = delta;
	printf("Input differences are: ");
	printbinary(delta); printf("\n");
    
	while(ret < 24) {
		// Find the first "1" in the input differences	
		while (temp % 2 == 0) {
			ret++;			
			temp = RROT24((temp), 1);						
		}
		
		// Compare to the pattern
		if (matchPattern(temp) == 1)
			return (ret - 3 > 0? (ret - 3): 21 + ret);
		else {
			ret++;
			temp = RROT24(temp, 1);	
		}
	}		
    return ret; 
}

uint8_t getFaultPosition64(uint32_t delta) {
    uint8_t ret = 0;
    uint32_t temp = delta;
	printf("Input differences are: ");
	printbinary(delta); printf("\n");
    
	while(ret < 32) {
		// Find the first "1" in the input differences	
		while (temp % 2 == 0) {
			ret++;			
			temp = RROT32((temp), 1);						
		}
		
		// Compare to the pattern
		if (matchPattern(temp) == 1)
			return (ret - 3 > 0? (ret - 3): 29 + ret);
		else {
			ret++;
			temp = RROT32(temp, 1);	
		}
	}		
    return ret; 
}

