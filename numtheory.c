#include "numtheory.h"

#include "randstate.h"

void gcd(mpz_t g, const mpz_t a, const mpz_t b){
    if (mpz_cmp_ui(b, 0) == 0 || mpz_cmp_ui(a, 0) == 0 || mpz_cmp_ui(a, 1) == 0 || mpz_cmp_ui(b, 1) == 0) { 
        mpz_set_ui(g, 0);
        return;
    }
    mpz_t copy_of_a, copy_of_b, t; 
    mpz_inits(copy_of_a, copy_of_b, t, NULL); 
    mpz_set(copy_of_a, a); 
    mpz_set(copy_of_b, b); 
    while (mpz_cmp_ui(copy_of_b, 0) != 0) { 
        mpz_set_ui(t, 0); 
        mpz_set(t, copy_of_b); 
        mpz_mod(copy_of_b, copy_of_a, copy_of_b); 
        mpz_set(copy_of_a, t); 
    }
    mpz_set(g, copy_of_a); 
    mpz_clears(copy_of_a, copy_of_b, t, NULL); 
    return;
}

void mod_inverse(mpz_t o, const mpz_t a, const mpz_t n) { 
    mpz_t r1, r2, t1, t2, temp1, temp2, q, q_mul_r, q_mul_t; 
    mpz_inits(r1, r2, t1, t2, temp1, temp2, q, q_mul_r, q_mul_t, NULL); 
    mpz_set(r1, n);
    mpz_set(r2, a); 
    mpz_set_ui(t1, 0); 
    mpz_set_ui(t2, 1); 
    while (mpz_cmp_ui(r2, 0) != 0) { 
        mpz_fdiv_q(q, r1, r2); 
        mpz_set(temp1, r1); 
        mpz_set(r1, r2); 
        mpz_mul(q_mul_r, q, r2); 
        mpz_sub(r2, temp1, q_mul_r); 
        mpz_set(temp2, t1); 
        mpz_set(t1, t2); 
        mpz_mul(q_mul_t, q, t2); 
        mpz_sub(t2, temp2, q_mul_t);
    }
    if (mpz_cmp_ui(r1, 1) > 0) {
        mpz_set_ui(o, 0);
        mpz_clears(r1, r2, t1, t2, temp1, temp2, q, q_mul_r, q_mul_t, NULL); 
        return;
    }
    if (mpz_cmp_ui(t1, 0) < 0) {
        mpz_add(t1, t1, n);
        mpz_set(o, t1);
        mpz_clears(r1, r2, t1, t2, temp1, temp2, q, q_mul_r, q_mul_t, NULL);
        return;
    }
    mpz_set(o, t1); 
    mpz_clears(r1, r2, t1, t2, temp1, temp2, q, q_mul_r, q_mul_t, NULL); 
    return;
}


void pow_mod(mpz_t o, const mpz_t a, const mpz_t d, const mpz_t n) {
    mpz_t v, p, copy_of_d, copy_of_d_1, temp; 
    mpz_inits(v, p, copy_of_d, copy_of_d_1, temp, NULL); 
    mpz_set_ui(v, 1); 
    mpz_set(p, a);
    mpz_set(copy_of_d, d);
    while (mpz_cmp_ui(copy_of_d, 0) > 0) { 
        if (mpz_mod_ui(copy_of_d_1, copy_of_d, 2) == 1) { 
            mpz_mul(temp, v, p); 
            mpz_mod(v, temp, n);
        }
        mpz_mul(temp, p, p); 
        mpz_mod(p, temp, n);
        mpz_tdiv_q_ui(copy_of_d, copy_of_d, 2); 
    }
    mpz_set(o, v);
    mpz_clears(v, p, copy_of_d, copy_of_d_1, temp, NULL);
    return;
}


bool is_prime(const mpz_t n, uint64_t iters) {
    mpz_t a, y, j, r, pow_mod_exp, n1, one; 
    mpz_inits(a, y, j, r, pow_mod_exp, n1, one, NULL); 
    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) { 
        mpz_clears(a, y, j, r, pow_mod_exp, n1, one, NULL); 
        return true; 
    }
    if ((mpz_divisible_ui_p(n, 2) != 0) || mpz_cmp_ui(n, 1) == 0 || mpz_cmp_ui(n, 0) == 0) { 
        mpz_clears(a, y, j, r, pow_mod_exp, n1, one, NULL); 
        return false; 
    }
    mp_bitcnt_t s, s1; 
    s = 1; 
    mpz_sub_ui(n1, n, 1); 
    int ab; 
    do {
        ab = mpz_divisible_2exp_p(n1, s);
        s++;
    } while (ab == 0); 
    mpz_set_ui(one, 1);
    mpz_mul_2exp(one, one, s);
    mpz_cdiv_q(r, n1, one);
    for (uint64_t i = 1; i < iters; i++) { 
        mpz_urandomm(a, state, n); 
        mpz_add_ui(a, a, 2); 
        pow_mod(y, a, r, n); 
        if ((mpz_cmp_ui(y, 1) != 0) && mpz_cmp(y, n1) != 0) { 
            mpz_set_ui(j, 1); 
            s1 = s - 1; 
            while ((mpz_cmp_ui(j, s1) <= 0) && mpz_cmp(y, n1) != 0) { 
                mpz_set_ui(pow_mod_exp, 2);
                pow_mod(y, y, pow_mod_exp, n); 
                if (mpz_cmp_ui(y, 1) == 0) { 
                    mpz_clears(a, y, j, r, pow_mod_exp, n1, one, NULL);
                    return false; 
                }
                mpz_add_ui(j, j, 1); 
            }
            if (mpz_cmp(y, n1) != 0) {
                mpz_clears(a, y, j, r, pow_mod_exp, n1, one, NULL); 
                return false; 
            }
        }
    }
    mpz_clears(a, y, j, r, pow_mod_exp, n1, one, NULL); 
    return true; 
}


void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    do {
        mpz_urandomb(p, state, bits); 
        mpz_setbit(p, 0);
        mpz_setbit(p, bits);
    } while (!is_prime(p, iters)); 
    return; 
}
