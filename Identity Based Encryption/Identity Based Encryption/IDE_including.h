//
//  IDE_including.h
//  Identity Based Encryption
//
//  Created by SUN Guodong and WANG Liang on 5/2/19.
//  Copyright © 2019 SUN Guden. All rights reserved.
//

#ifndef IDE_including_h
#define IDE_including_h

#include "pbc-0.5.14/include/pbc.h"
#include "gmp-6.1.2/gmp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"

// Declare the 
void get_private_key(char* ID, pairing_t pairing, element_t s, element_t Sid);
void get_public_key(char* ID, pairing_t pairing, element_t Qid);
void encryption(char* shamessage, char* ID, element_t P, element_t Ppub,
                element_t U, char* V, pairing_t pairing);
void decryption(element_t Sid, pairing_t pairing, element_t U, char* V,
                char* xor_result_receiver);
void setup_sys(int rbits, int qbits, element_t P, element_t Ppub,
               pairing_t pairing, element_t s);

#endif /* IDE_including_h */
