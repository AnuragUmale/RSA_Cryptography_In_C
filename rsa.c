#include <stdio.h> // clang-format off
// clang-format on
#include "numtheory.h" 
#include "randstate.h"
#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>



void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters)
{
    mpz_t totient, p1, q1, gcd_val, lambda, temp_e, gcds,j; 
    mpz_inits(totient, p1, q1, gcd_val, lambda, temp_e, gcds, j,NULL);
    uint64_t pbits = random() % ((3 * nbits / 4) - (nbits / 4)) + 1 + (nbits / 4); 
    make_prime(p, pbits, iters);
    uint64_t qbits = nbits - pbits;
    make_prime(q, qbits, iters);
    mpz_mul(n, p, q);
    mpz_sub_ui(p1, p, 1); 
    mpz_sub_ui(q1, q, 1);
    mpz_mul(totient, p1, q1);
    gcd(gcd_val, p1, q1); 
    mpz_tdiv_q(lambda, totient, gcd_val);
    mpz_set(j, lambda); 
    mpz_urandomb(temp_e, state, nbits);
    while (true){ 
        mpz_urandomb(temp_e, state, nbits);
        gcd(gcds, temp_e, lambda);
        if (mpz_sizeinbase(temp_e, 2) >= nbits && mpz_cmp_ui(gcds, 1) == 0)
        {
            mpz_set(e, temp_e);
            break;
        }
    }
    mpz_clears(totient, p1, q1, gcd_val, lambda, temp_e, gcds, j, NULL);
}

void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q)
{
    mpz_t totient, p1, q1, gcdval, lambda ,j; 
    mpz_inits(totient, p1, q1, gcdval, lambda, j, NULL);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(totient, p1, q1);
    gcd(gcdval, p1, q1);
    mpz_tdiv_q(lambda, totient, gcdval);
    mpz_set(j, lambda);
    mod_inverse(d, e, j);
    mpz_clears(totient, p1, q1, gcdval, lambda,j,NULL);
}

void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile){
    gmp_fprintf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
}

void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile){
    gmp_fscanf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
}

void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile){
    gmp_fprintf(pvfile, "%Zx\n%Zx\n", n, d);
}

void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile){
    gmp_fscanf(pvfile, "%Zx\n%Zx\n", n, d);
}

void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) { 
    pow_mod(c, m, e, n); 
}

void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) { 
    pow_mod(m, c, d, n); 
}

void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e){
    mpz_t copy_of_n, c, m;
    mpz_inits(copy_of_n, c, m, NULL);
    mpz_set(copy_of_n, n); 
    int count = 0;
    while (mpz_cmp_ui(copy_of_n, 0) != 0)
    {
        mpz_tdiv_q_ui(copy_of_n, copy_of_n, 2);
        count++;
    }
    int k = (count - 1) / 8;
    uint8_t *arr = (uint8_t *)malloc(k * sizeof(uint8_t));
    while (feof(infile) == 0){
        arr[0] = 0xFF;
        size_t size = fread(arr + 1, 1, k - 1, infile);
        mpz_import(m, size + 1, 1, sizeof(uint8_t), 1, 0, arr);
        rsa_encrypt(c, m, e, n);
        gmp_fprintf(outfile, "%Zx\n",c);
    }
    free(arr);
    mpz_clears(copy_of_n, c, m, NULL);
}

void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d){
    mpz_t copy_of_n, c, m;
    mpz_inits(copy_of_n, c, m, NULL);
    mpz_set(copy_of_n, n);
    int count = 0;
    while (mpz_cmp_ui(copy_of_n, 0) != 0){
        mpz_tdiv_q_ui(copy_of_n, copy_of_n, 2);
        count++;
    }
    int k = (count - 1) / 8;
    uint8_t *arr = (uint8_t *)malloc(k * sizeof(uint8_t));
    while (feof(infile) == 0){ 
        if (gmp_fscanf(infile, "%Zx", c) > 0){
            rsa_decrypt(m, c, d, n);
            size_t size;
            mpz_export(arr, &size, 1, sizeof(uint8_t), 1, 0, m);
            fwrite(arr + 1, sizeof(uint8_t), size - 1, outfile); 
        }
    }
    mpz_clears(copy_of_n, c, m, NULL); 
    free(arr);
}

void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) { 
    pow_mod(s, m, d, n); 
}

bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n){
    mpz_t t;
    mpz_init(t);
    pow_mod(t, s, e, n);
    if (mpz_cmp(t, m) == 0){
        mpz_clear(t);
        return true;
    }
    else{
        mpz_clear(t);
        return false;
    }
}
