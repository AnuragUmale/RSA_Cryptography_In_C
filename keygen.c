#include <stdio.h> 	// clang-format off
// clang-format on
#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
#include <gmp.h>
#include <math.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h> 
#include <unistd.h>

void verbose(char *username, mpz_t s, mpz_t p, mpz_t q, mpz_t n, mpz_t e, mpz_t d){
  fprintf(stderr, "username: %s\n", username);
  gmp_fprintf(stderr, "user signature: (%zu bits) %Zd\n", mpz_sizeinbase(s, 2),s);
  gmp_fprintf(stderr, "p (%zu bits) %Zd\n", mpz_sizeinbase(p, 2), p);
  gmp_fprintf(stderr, "q (%zu bits) %Zd\n", mpz_sizeinbase(q, 2), q);
  gmp_fprintf(stderr, "n - modulus (%zu bits) %Zd\n", mpz_sizeinbase(n, 2), n);
  gmp_fprintf(stderr, "e - public exponent (%zu bits) %Zd\n",mpz_sizeinbase(e, 2), e);
  gmp_fprintf(stderr, "d - private exponent (%zu bits) %Zd\n", mpz_sizeinbase(d, 2), d);
}

void help(void)
{
  fprintf(stderr, "Usage: ./keygen [options]\n");
  fprintf(stderr, "  ./keygen generates a public / private key pair, placing the keys into the public and private\n");
  fprintf(stderr, "  key files as specified below. The keys have a modulus (n) whose length is specified in\n");
  fprintf(stderr, "  the program options.\n");
  fprintf(stderr, "    -s <seed>   : Use <seed> as the random number seed. Default: time(NULL)\n");
  fprintf(stderr, "    -b <bits>   : Public modulus n must have at least <bits> bits. Default: 1024\n");
  fprintf(stderr, "    -i <iters>  : Run <iters> Miller-Rabin iterations for primality testing. Default: 50\n");
  fprintf(stderr, "    -n <pbfile> : Public key file is <pbfile>. Default: rsa.pub\n");
  fprintf(stderr, "    -d <pvfile> : Private key file is <pvfile>. Default: rsa.priv\n");
  fprintf(stderr, "    -v          : Enable verbose output.\n");
  fprintf(stderr, "    -h          : Display program synopsis and usage.\n");
}

#define OPTIONS "b:i:n:d:svh" 
int main(int argc, char **argv)
{
  int opt = 0;
  uint64_t bits = 1024;
  uint64_t iters = 50; 
  char *filename = "rsa.pub";
  char *filename1 = "rsa.priv";
  uint64_t seed = (uint64_t)time(NULL);
  char *username = getenv("USER"); 
  int ver = 0; 
  while ((opt = getopt(argc, argv, OPTIONS)) != -1){ 
    switch (opt){ 
    case 'b': 
      if (atoi(optarg) < 50 || atoi(optarg) > 4096)
      {
        fprintf(stderr,"Number of bits must be 50-4096, not %d.\n", atoi(optarg));
        help();
        exit(-1);
      }
      else
      {
        bits = atoi(optarg); 
      }
      break;
    case 'i':
      if (atoi(optarg) < 1 || atoi(optarg) > 500)
      {
        fprintf(stderr,"Number of iterations must be 1-500, not %d.\n", atoi(optarg));
        help();
        exit(-1);
      }
      else
      {
        iters = atoi(optarg); 
      }
      break;
    case 'n':
      filename = optarg; 
      break;

    case 'd':
      filename1 = optarg;
      break;
    case 's':
      seed = atoi(optarg); 
      break;
    case 'v':
      ver = 1;
      break;
    case 'h':
      help(); 
      exit(0);
    default: 
      help();
      exit(-1);
    }
  }
  FILE *pbfile = fopen(filename, "w");
  if (pbfile == NULL){ 
    help();
    return 1;
  }
  FILE *pvfile = fopen(filename1, "w");
  if (pvfile == NULL){
    help();
    fclose(pbfile);
    return 1;
  }
  fchmod(fileno(pvfile), 0600); 
  randstate_init(seed); 
  mpz_t p, q, n, e, d, user, s, m; 
  mpz_inits(p, q, n, e, d, user, s, m, NULL);
  rsa_make_pub(p, q, n, e, bits, iters);
  rsa_make_priv(d, e, p, q);
  mpz_set_str(user, username, 62);
  rsa_sign(s, user, d, n); 
  rsa_write_pub(n, e, s, username, pbfile);
  rsa_write_priv(n, d, pvfile); 
  if (ver == 1){ 
    verbose(username, s, p, q, n, e, d);
  }
  fclose(pbfile);
  fclose(pvfile);
  mpz_clears(p, q, n, e, d, user, s, m, NULL);
  randstate_clear();
  return 0;
}
