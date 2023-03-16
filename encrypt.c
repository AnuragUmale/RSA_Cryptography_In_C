#include <stdio.h> // clang-format off
// clang-format on
#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
#include <gmp.h>
#include <getopt.h>
#include <math.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define OPTIONS "i:o:n:vh" 

void verbose(char *username, mpz_t s, mpz_t n, mpz_t e){
  fprintf(stderr, "username: %s\n", username);
  gmp_fprintf(stderr, "user signature: (%zu bits) %Zd\n", mpz_sizeinbase(s, 2),s);
  gmp_fprintf(stderr, "n - modulus (%zu bits) %Zd\n", mpz_sizeinbase(n, 2), n);
  gmp_fprintf(stderr, "e - public exponent (%zu bits) %Zd\n", mpz_sizeinbase(e, 2), e);
}

void help(){
  fprintf(stderr, "Usage: ./encrypt [options]\n");
  fprintf(stderr, "  ./encrypt encrypts an input file using the specified public key file,\n");
  fprintf(stderr, "  writing the result to the specified output file.\n");
  fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: standard input.\n");
  fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: standard output.\n");
  fprintf(stderr, "    -n <keyfile>: Public key is in <keyfile>. Default: rsa.pub.\n");
  fprintf(stderr, "    -v          : Enable verbose output.\n");
  fprintf(stderr, "    -h          : Display program synopsis and usage.\n");
}




int main(int argc, char **argv)
{
  int opt = 0;
  FILE *infile = stdin;                 
  FILE *outfile = stdout;               
  char *filename = "rsa.pub";           
  uint64_t seed = (uint64_t)time(NULL); 
  char *username = getenv("USER");      
  int ver = 0;                       
  while ((opt = getopt(argc, argv, OPTIONS)) != -1){ 
    switch (opt)
    {      
    case 'i': 
      infile = fopen(optarg, "r");
      if (infile == NULL){
        fprintf(stderr,"Error: Failed to open the file %s\n", optarg);
        return 1;
      }
      break;
    case 'n':
      filename = optarg;
      break; 

    case 'o':
      outfile = fopen(optarg, "w");
      break;
    case 'v':
      ver = 1;
      break;
    case 'h':
      help();
      exit(0);
    default:
      help();
      exit(1);
    }
  }
  FILE *pbfile = fopen(filename, "r");
  if (pbfile == NULL){
    fclose(infile);
    fclose(outfile);
    help();
    return 1;
  }
  randstate_init(seed);
  mpz_t n, user, e, s;
  mpz_inits(n, e, user, s, NULL);
  rsa_read_pub(n, e, s, username,pbfile);
  mpz_set_str(user, username, 62); 
  if (rsa_verify(user, s, e, n) == false){
    fprintf(stderr,"Invalid Signature\n");
    return 1;
  }
  rsa_encrypt_file(infile, outfile, n, e);
  if (ver == 1){
    verbose(username, s, n, e);
  }
  fclose(pbfile);
  fclose(infile);
  fclose(outfile);
  mpz_clears(n, e, user, s, NULL);
  randstate_clear();
  return 0;
}