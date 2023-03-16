#include <stdio.h> // clang-format off
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

#define OPTIONS "i:o:n:vh"


void verbose(mpz_t n, mpz_t d)
{
  gmp_fprintf(stderr, "n - modulus (%zu bits) %Zd\n", mpz_sizeinbase(n, 2), n);
  gmp_fprintf(stderr, "d - private exponent (%zu bits) %Zd\n", mpz_sizeinbase(d, 2), d);
}

void help()
{
  fprintf(stderr, "Usage: ./decrypt [options]\n");
  fprintf(stderr, "  ./decrypt decrypts an input file using the specified private key file,\n");
  fprintf(stderr, "  writing the result to the specified output file.\n");
  fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: standard input.\n");
  fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: standard output.\n");
  fprintf(stderr, "    -n <keyfile>: Private key is in <keyfile>. Default: rsa.priv.\n");
  fprintf(stderr, "    -v          : Enable verbose output.\n");
  fprintf(stderr, "    -h          : Display program synopsis and usage.\n");
}


int main(int argc, char **argv)
{
  int opt = 0;
  FILE *infile = stdin;
  FILE *outfile = stdout;               
  char *filename = "rsa.priv";
  uint64_t seed = (uint64_t)time(NULL);
  int ver = 0;               
  while ((opt = getopt(argc, argv, OPTIONS)) != -1){ 
    switch (opt){
    case 'i':
      infile = fopen(optarg, "r");
      if (infile == NULL){
        printf("Error: Failed to open the file %s\n", optarg);
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
  FILE *pvfile = fopen(filename, "r");
  if (pvfile ==  NULL){
    help();
    fclose(infile);
    fclose(outfile);
    return 1;
  }
  randstate_init( seed);  
  mpz_t n, d;
  mpz_inits(n, d, NULL);
  rsa_read_priv(n, d, pvfile); 
  rsa_decrypt_file(infile, outfile, n, d);
  if (ver == 1){
    verbose(n, d);
  }
  fclose(pvfile);
  fclose(infile);
  fclose(outfile);
  mpz_clears(n, d, NULL);
  randstate_clear();
  return 0;
}