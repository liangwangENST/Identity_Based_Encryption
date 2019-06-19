//
//  main.cpp
//  Identity Based Encryption
//
//  Created by SUN Guodong and Liang Wang on 5/2/19.
//  Copyright © 2019 SUN Guodong. All rights reserved.
//


#include "IDE_including.h"

#define SIZE 100
#define RBITS 160
#define QBITS 512

//
void get_private_key(char* ID, pairing_t pairing, element_t s, element_t Sid)
{
    element_t PublicKey, PrivateKey;
    element_init_G1(PublicKey, pairing);
    element_init_G1(PrivateKey, pairing);
    
    element_from_hash(PublicKey, ID, strlen(ID));   //Compute user public key
    element_mul_zn(PrivateKey, PublicKey, s);   //Compute user private key
    element_printf("Private key Sid = %B\n", PrivateKey);
    Sid = PrivateKey;
    
}

void get_public_key(char* ID, pairing_t pairing, element_t Qid)
{
    
    element_t PublicKey, PrivateKey;
    element_init_G1(PublicKey, pairing);
    element_init_G1(PrivateKey, pairing);
    
    element_from_hash(PublicKey, ID, strlen(ID));   //Compute user public key
    element_printf("\nPublic key Qid = %B\n", PublicKey);
    Qid = PublicKey;
    
}


void encryption(char* shamessage, char* ID, element_t P, element_t P_pub,
                element_t U, char* V, pairing_t pairing)
{
    int i;
    char sgid[SIZE];   //Sender gid string representation
    char shagid[SIZE];
    
    element_t r;
    element_t Qid;
    element_t gid;
    element_init_G1(Qid, pairing);
    element_init_GT(gid, pairing);
    element_init_Zr(r, pairing);
    element_random(r);
    element_mul_zn(U, P, r);
    element_printf("U = %B", U);
    get_public_key(ID, pairing, Qid);
    element_pairing(gid, Qid, P_pub);
    element_pow_zn(gid, gid, r);
    element_snprint(sgid, SIZE, gid);
    sha_fun(sgid, shagid);
    
    //Do the XOR operation to the shamessage and shagid
    for (i = 0; i < 40; i++) {
        xor_operation(shamessage[i], shagid[i], V);
    }
    
    printf("\nV=%s\n", V);
    
}

void decryption(element_t Sid, pairing_t pairing, element_t U, char* V,
                char* xor_result_receiver)
{
    
    int i;
    element_t rgid;
    char sgid_receiver[SIZE]; //Receiver calculated gid string representation
    char shagid_receiver[SIZE]; //Receiver H2 function result
    element_init_GT(rgid, pairing);
    element_pairing(rgid, Sid, U);
    element_snprint(sgid_receiver, SIZE, rgid);
    sha_fun(sgid_receiver, shagid_receiver);  //Generate H2(e(dID,U));
    
    //XOR V and the hash result above
    for (i = 0; i < 40; i++) {
        xor_operation(V[i], shagid_receiver[i], xor_result_receiver);
    }
    
}

void setup_sys(int rbits,int qbits, element_t P,element_t Ppub,pairing_t pairing,element_t s )
{
    
    pbc_param_t par;   //Parameter to generate the pairing
    pbc_param_init_a_gen(par, rbits, qbits); //Initial the parameter for the pairing
    pairing_init_pbc_param(pairing, par);   //Initial the pairing
    
    //Using symmetric pairing
    if (!pairing_is_symmetric(pairing))
        pbc_die("pairing must be symmetric");
    
    element_init_G1(P, pairing);
    element_init_G1(Ppub, pairing);
    element_init_Zr(s, pairing);
    element_random(P);
    element_random(s);
    element_mul_zn(Ppub, P, s);
    
}

int main()
{
    //Declare the variables.
    char qbits[5];
    char rbits[5];
    char ID[SIZE];   //User ID
    char message[SIZE];   //User message
    char shamessage[SIZE]; //The input message digest(sha1 result)
    
    char xor_result[SIZE]; //Sender XOR result---V
    char xor_result_receiver[SIZE];  //Receiver XOR result
    memset(xor_result, 0, sizeof(char)*SIZE);
    memset(xor_result_receiver, 0, sizeof(char)*SIZE);
    
    pairing_t pairing;
    
    element_t P, Ppub, s, U, Qid, Sid;
    mpz_t messagehash;
    mpz_init(messagehash);
    
    printf("\n############SETUP############\n");
    printf("Please enter security parameter \'rbits\':");
    scanf("%[0-9]", rbits);
    getchar();
    printf("\nPlease enter security parameter \'qbits\':");
    scanf("%[0-9]", qbits);
    getchar();
    
    setup_sys(atoi(rbits), atoi(qbits), P, Ppub, pairing, s);
    printf("System parameters have been set!\n");
    
    element_printf("The random generator P = %B\n", P);
    element_printf("The public system parameter Ppub = %B\n", Ppub);
    
    
    printf("###########EXTRACT###########\n");
    element_init_G1(Qid, pairing);
    element_init_G1(Sid, pairing);
    
    printf("Plase enter your ID:");
    scanf("%[ a-zA-Z0-9+*-!.,&*@{}$#]", ID);
    printf("\n\'ID=%s\' is used as public key to encrypt the message\n", ID);
    getchar();
    get_private_key(ID, pairing, s, Sid);
    get_public_key(ID, pairing, Qid);
    
    printf("##########ENCRPTION##########\n");
    printf("\nPlase enter the message to encrypt:");
    scanf("%[ a-zA-Z0-9+*-!.,&*@{}$#]", message);
    getchar();
    printf("The original message=%s", message);
    
    //shamessage is send to recevier for comparison.
    sha_fun(message, shamessage);   //Get the message digest
    printf("\nThe message hash=%s\n", shamessage);
    
    element_init_G1(U, pairing);
    encryption(shamessage, ID, P, Ppub, U, xor_result, pairing);
    
    printf("Send <U,V> to the receiver!\n");
    
    printf("##########DECRYPTION##########");
    decryption(Sid, pairing, U, xor_result, xor_result_receiver);
    printf("\nThe recovery message digest is %s\n", xor_result_receiver);
    printf("We compare the recovery message with the original message in bitwise by hashed message\n");
    printf("The original message digest is %s\n", shamessage);
    
    if (strcmp(xor_result_receiver, shamessage) == 0) {
        
        printf("Yeah!The message has been decrpted!\n");
    }
    
    else {
        printf("Oops!The message can not be decrpted properly!\n");
    }
    
    //Free space
    element_clear(P);
    element_clear(Ppub);
    element_clear(Qid);
    element_clear(Sid);
    element_clear(U);
    element_clear(s);
    pairing_clear(pairing);
    
    return 0;
}
