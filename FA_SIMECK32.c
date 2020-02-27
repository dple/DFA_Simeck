#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "simeck.h"

void printbinary(uint16_t x);
int matchPattern(uint16_t data);
uint8_t getFaultPosition(uint16_t delta);
int satisfatory(uint8_t array[], int size);
int satisfatoryMaster(uint8_t *array, int size);
int rightPosition(int pos);
void delay(int number_of_seconds);
void getK1(uint16_t cipher[2], uint16_t constant, uint32_t seq, uint16_t tempkeys[4]);
void getMasterkey(uint16_t cipher[2], uint16_t constant, uint32_t seq, uint16_t keys[4]);

const int NUM_ROUNDS = 32;    
const int8_t WORD_SIZE = 16;    

int main(void) {

    /* Plaintext and Key used to encrypt */
	uint16_t text[] = {
        0x6877,
        0x6565,
    };
    const uint16_t key[] = {
        0x0100,
        0x0908,
        0x1110,
        0x1918,
    };
    
    /* Assign values for a cipher computed */
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;	       
    const uint16_t *master_key = key; 
    const uint16_t *plaintext = text; 

    int idx;
    uint16_t ciphertext[2]; 

    uint16_t keys[4] = {
        master_key[0],
        master_key[1],
        master_key[2],
        master_key[3],
    };

	ciphertext[0] = plaintext[0];
    ciphertext[1] = plaintext[1];
    uint16_t temp;

    for (idx = 0; idx < NUM_ROUNDS - 5; idx++) {
        ROUND32(
                keys[0],
                ciphertext[1],
                ciphertext[0],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
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
		
    srand(time(NULL));

    getK1(ciphertext, constant, sequence, keys);    
    getMasterkey(ciphertext, constant, sequence, keys);    
}

void getMasterkey(uint16_t cipher[2], uint16_t constant, uint32_t seq, uint16_t keys[4]) {
    
    uint16_t correctcipher[2];  // for encryption correct text
    uint16_t faultycipher[2];   // for encryption faulty text
    uint8_t stateKeys[4][WORD_SIZE];        // Record if a key bit recovered from K(T - 1) to K(T - 4): 1 - recovered, 0 - not recovered
    uint8_t stateDelta[2][WORD_SIZE];       // Indicate if bits of Delta(T - 3), Delta(T - 4) are known: 1 -  known, 0 - unknown
    uint16_t tempkeys[4]; 
    uint16_t correcttext[6]; //uint16_t correcttext[6][2]; // imm     
	uint16_t faultytext[6]; //uint16_t faultytext[6][2];
    uint16_t delta[6];   //uint16_t delta[6][2];    
    uint16_t temp;
    int temppos;
    int8_t pos;                 // Position where a fault is injected
    int8_t faultpos;            // Deduce from pattern recognization 
	int n_faults = 0;           // Number of faults to fully recover K(T - 1)
    int sum_faults = 0;         // Total number of faults after 10000 times
    
    int i, j, idx;

    for (idx = 0; idx < 10000; idx++)
    {           
        n_faults = 0; // Initialize the number of bits injected

        /* Initialize the state array, indicating that all bits not yet recovered */
        for (i = 0; i < 4; i++)
            for (j = 0; j < WORD_SIZE; j++)
                stateKeys[i][j] = 0;
            
                    
        while (!satisfatoryMaster((uint8_t *)stateKeys, WORD_SIZE))
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
            correcttext[0] = cipher[1];
            faultytext[0] = FLIPBIT(cipher[1], pos); //faultytext[0][0] = ciphertext[0];
            
            // Set immediate correct and faulty ciphertext as ones at round T - 5
            correctcipher[0] = cipher[0];
            correctcipher[1] = cipher[1]; 
            faultycipher[0] = cipher[0];            
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

                constant &= 0xFFFC;
                constant |= seq & 1;
                seq >>= 1;
                ROUND32(
                        constant,
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
            faultpos = getFaultPosition(delta[3]);		

            /* Determine known bits of Delta(T - 3) and Delta(T - 4) from the fault position recovered */
            for (j = 2; j < 5; j++){
                stateDelta[0][rightPosition(faultpos + j)] = 1;      // stateDelta[0] is Delta(T - 3)
                stateDelta[1][rightPosition(faultpos + j)] = 1;      // stateDelta[1] is Delta(T - 4)
            }
            stateDelta[1][rightPosition(faultpos + 1)] = 1;

            for (j = 7; j < 10; j++){
                stateDelta[0][rightPosition(faultpos + j)] = 1;
                stateDelta[1][rightPosition(faultpos + j)] = 1;      
            }
            stateDelta[1][rightPosition(faultpos + 6)] = 1;      // stateDelta[1] is Delta(T - 4)
            
            for (j = 11; j < WORD_SIZE; j++){
                stateDelta[0][rightPosition(faultpos + j)] = 1;
                stateDelta[1][rightPosition(faultpos + j)] = 1;      // stateDelta[1] is Delta(T - 4)
            }
            stateDelta[1][rightPosition(faultpos + 10)] = 1;      
            /*
            printf("Fault position is: %d \n", faultpos);
            for (j = 0; j < WORD_SIZE; j++)
            {
                printf(" %d ", stateDelta[1][j]);
            }
            printf("\n");*/
            
            // Recover key bits from linear expressions, Step 4.1
            stateKeys[0][rightPosition(faultpos - 2)] = 1;           // stateKeys[0] means K(T - 1)
            stateKeys[0][rightPosition(faultpos + 8)] = 1;       
            stateKeys[1][rightPosition(faultpos - 3)] = 1;           // stateKeys[0] means K(T - 2)
            stateKeys[1][rightPosition(faultpos + 7)] = 1;       
            stateKeys[2][rightPosition(faultpos - 4)] = 1;           // stateKeys[0] means K(T - 3)
            stateKeys[2][rightPosition(faultpos + 6)] = 1;       
            stateKeys[3][rightPosition(faultpos - 5)] = 1;           // stateKeys[0] means K(T - 4)
            stateKeys[3][rightPosition(faultpos + 5)] = 1;       
            // Recover bits from Step 4.2
            for (i = 0; i < WORD_SIZE; i++)
            {
                // Recover K(T - 1)
                if (GETBIT(delta[3], i)  == 1){           // Delta(T - 2)
                    if ((GETBIT(delta[3], rightPosition(i - 5))  == 0) && (stateDelta[0][i] == 1))
                        stateKeys[0][rightPosition(i - 5)] = 1;              
                }
                if (GETBIT(delta[3], i)  == 1){
                    if ((GETBIT(delta[3], rightPosition(i + 5))  == 0) && (stateDelta[0][rightPosition(i + 5)] == 1))
                        stateKeys[0][rightPosition(i + 5)] = 1;              
                }
                // Recover K(T - 2)
                if (GETBIT(delta[2], i)  == 1){           // Delta(T - 3)
                    if ((GETBIT(delta[2], rightPosition(i - 5))  == 0) && (stateDelta[1][i] == 1))
                        stateKeys[1][rightPosition(i - 5)] = 1;              
                }
                if (GETBIT(delta[2], i)  == 1){
                    if ((GETBIT(delta[2], rightPosition(i + 5))  == 0) && (stateDelta[1][rightPosition(i + 5)] == 1))
                        stateKeys[0][rightPosition(i + 5)] = 1;              
                }
                // Recover K(T - 3)
                if ((GETBIT(delta[1], i)  == 1) && (GETBIT(delta[1], rightPosition(i - 5))  == 0))            // Delta(T - 4)                    
                        stateKeys[2][rightPosition(i - 5)] = 1;                              
                if ((GETBIT(delta[2], i)  == 1) && (GETBIT(delta[2], rightPosition(i + 5))  == 0))
                        stateKeys[0][rightPosition(i + 5)] = 1;              
            }   
        } 
        //printf("No of faults to recover master key: %d \n", n_faults);
        sum_faults += n_faults;         //printf("Sum fauts is: %d\n", sum_faults);

        //delay(1);        // Delay to refresh a new random seed
    }
    printf("Simeck32/64 %04x %04x\n", correctcipher[1], correctcipher[0]);            
    printf("Average number of faults injected to recover the full master key: %f\n", (double)sum_faults/10000);
}

/***
 * Get the last round key
 */
void getK1(uint16_t cipher[2], uint16_t constant, uint32_t seq, uint16_t keys[4]) {
    uint8_t state[WORD_SIZE];       // Record if a bit recovered: 1 - recovered, 0 - not recovered
    uint8_t deltaT3[WORD_SIZE];     // Indicate if bits of Delta(T - 3) are known: 1 -  known, 0 - unknown
    uint8_t stateFault[WORD_SIZE];
    uint16_t correctcipher[2];  // for encryption correct text
    uint16_t faultycipher[2];   // for encryption faulty text

    uint16_t correcttext[6];    // Correct left inputs from fault 
	uint16_t faultytext[6];     // Faulty left inputs from fault
    uint16_t delta[6];          // Input differences from fault 
    uint16_t tempkeys[4]; 
    uint16_t temp;
    int temppos;
    int8_t pos;                 // Position where a fault is injected
    int8_t faultpos;            // Deduce from pattern recognization 
	int n_faults = 0;           // Number of faults to fully recover K(T - 1)
    int sum_faults = 0;         // Total number of faults after 10000 times
    
    int idx;
    int i, j;

    for (i = 0; i < 10000; i++)
    {   
        n_faults = 0; // Initialize the number of bits injected

        /* Initialize the state array, indicating that all bits not yet recovered */
        for (idx = 0; idx < WORD_SIZE; idx++){
            state[idx] = 0;
            stateFault[idx] = 0;
        }
                    
        while (!satisfatory(state, WORD_SIZE)) //&& (n_faults) < 100)
        {
            n_faults +=1;

            /* Initialize the array of Delta(T - 3), indicating that all bits not yet known */
            for (j = 0; j < WORD_SIZE; j++)            
                deltaT3[j] = 0;
            
            for (idx = 0; idx < 4; idx++)
                tempkeys[idx] = keys[idx];
            
            // Inject a fault into the input at the round T - 5
            pos = rand() % WORD_SIZE;   // pos = 1; 
            // correcttext and faultytext will be used to compute input differences from round T - 5 to T
            correcttext[0] = cipher[1];
            faultytext[0] = FLIPBIT(cipher[1], pos);
            
            // Set immediate correct and faulty ciphertext as ones at round T - 5
            correctcipher[0] = cipher[0];
            correctcipher[1] = cipher[1]; 
            faultycipher[0] = cipher[0];            
            faultycipher[1] = faultytext[0];        
            
            // Initialize input differences
            delta[0] = faultytext[0] ^ correcttext[0]; 
            //printf("Delta(T - 5) of fault position %d: ", pos); printbinary(delta[0]); printf("\n");            

            for (idx = 0; idx < 5; idx++) {	
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

                constant &= 0xFFFC;
                constant |= seq & 1;
                seq >>= 1;
                ROUND32(
                        constant,
                        tempkeys[1],
                        tempkeys[0],
                        temp
                );
                
                // rotate the LFSR of keys
                temp = tempkeys[1];
                tempkeys[1] = tempkeys[2];
                tempkeys[2] = tempkeys[3];
                tempkeys[3] = temp;
                
                correcttext[idx + 1] = correctcipher[1]; 
                faultytext[idx + 1] = faultycipher[1];   
                delta[idx + 1] = faultytext[idx + 1] ^ correcttext[idx + 1]; 
            }     
            
            /* Get the fault position by matching pattern of delta T - 2 */            
            faultpos = getFaultPosition(delta[3]);		
            stateFault[faultpos] = 1;
            //printf("Delta(T - 2) at the fault %d: ", faultpos); printbinary(delta[3]); printf("\n");            

            /* Determine known bits of Delta(T - 3) from the fault position recovered */
            for (j = 2; j < 5; j++)
                deltaT3[rightPosition(faultpos + j)] = 1;
            for (j = 7; j < 10; j++)
                deltaT3[rightPosition(faultpos + j)] = 1;

            for (j = 11; j < WORD_SIZE; j++)
                deltaT3[rightPosition(faultpos + j)] = 1;
            
            // Recover bits from linear expressions, Step 4.1
            state[rightPosition(faultpos - 2)] = 1;
            state[rightPosition(faultpos + 8)] = 1;       
            // Recover bits from Step 4.2
            for (idx = 0; idx < WORD_SIZE; idx++)
            {
                if (GETBIT(delta[3], idx)  == 1){
                    if ((GETBIT(delta[3], rightPosition(idx - 5))  == 0) && (deltaT3[idx] == 1))
                        state[rightPosition(idx - 5)] = 1;              
                }
                if (GETBIT(delta[3], idx)  == 1){
                    if ((GETBIT(delta[3], rightPosition(idx + 5))  == 0) && (deltaT3[rightPosition(idx + 5)] == 1))
                        state[rightPosition(idx + 5)] = 1;              
                }                
            }
                        
                
        } 
        //printf("No of faults to recover K1: %d \n", n_faults);
        sum_faults += n_faults;                 
    }
    printf("Simeck32/64 %04x %04x\n", correctcipher[1], correctcipher[0]);            
    printf("Average number of faults injected to recover K(T - 1): %f\n", (double)sum_faults/10000);
}

/**
 * Make a delay for number_of_seconds seconds
 */
void delay(int number_of_seconds) 
{ 
    // Converting time into clock cycles 
    int clock_cycles = CLOCKS_PER_SEC * number_of_seconds; 
      
    clock_t start_time = clock();       
    while (clock() < start_time + clock_cycles) 
        ; 
} 

/**
 * Return the right position of bit 
 */
int rightPosition(int pos) {    
    if (pos < 0){
        return 16 + pos;
    }
    else {
        if (pos > 15)
        {
            return pos - 16;
        }
        else
        {
            return pos;
        }
    }
}

/***
 * Check if all elements of array are 1
 */
int satisfatory(uint8_t array[], int size) {
    
    for (size_t i = 0; i < size; i++)
    {
        if (array[i] == 0)
        {
            return 0;
        }
        
    }
    return 1;
}


int satisfatoryMaster(uint8_t *array, int size) {
    
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
        printf("%d", GETBIT(x, i)); 
    }    
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
uint8_t getFaultPosition(uint16_t delta) {
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
			return (ret - 3 >= 0? (ret - 3): 13 + ret);
		else {
			ret++;
			temp = RROT16(temp, 1);	
		}
	}		
    return ret; 
}