#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "bliss_b_params.h"
#include "ntt_api.h"

/* Constructs a random polyomial
   - v: where the random polynomial is stored
   - n: the length of the polynomial
   - nz1: the number of coefficients that are +-1
   - nz2: the number of coefficients that are +-2
   - entropy: an initialized source of randomness   */
void uniform_poly(int32_t v[], uint32_t n, uint32_t nz1, uint32_t nz2, entropy_t *entropy) {
  uint32_t i, j;
  uint16_t x;
  int32_t mask;

  for (i = 0; i < n; i++){
    v[i] = 0;
  }
  
  i = 0;
  while (i < nz1) {
    x = entropy_random_uint16(entropy);  
    j = (x >> 1) % n;               // nb: uniform because n is a power of 2
    mask = -(1^(v[j]&1));           // mask = 1...1 if v[j] == 0 else 0
    i += mask&1;                    // add 1 only if v[j] == 0
    v[j] += (-1 + ((x&1)<<1))&mask; // v[j] = -1 if x&1 == 0 else 1
  }

  i = 0;
  while (i < nz2) {
    x = entropy_random_uint16(entropy);
    j = (x >> 1) % n;                     // nb: uniform because n is a power of 2
    mask = -(1^((v[j]&1)|((v[j]&2)>>1))); // mask = 1...1 if v[j] == 0 or v[j] == 1 else 0
    i += mask&1;                          // add 1 only if v[j] == 0 or v[j] == 1
    v[j] += (-2 + ((x&1)<<2))&mask;       // v[j] = -2 if x&1 == 0 else 2
  }
}

#if 0
// BD: for debugging
static void check_key(bliss_private_key_t *key, bliss_param_t *p, ntt_state_t state) {
  int32_t aux[512];
  uint32_t i, n;
  int32_t q;

  assert(key->kind == p->kind);
  
  n = p->n;
  q = p->q;
  
  // compute product key->s1 * key->a
  multiply_ntt(state, aux, key->s1, key->a);
  
  printf("a * s1:\n");
  for (i=0; i<n; i++) {
    printf(" %d", aux[i]);
    if ((i & 15) == 15) printf("\n");
  }
  printf("\n");

  printf("s1:\n");
  for (i=0; i<n; i++) {
    printf(" %d", key->s1[i]);
    if ((i & 15) == 15) printf("\n");
  }
  printf("\n");

  printf("s2:\n");
  for (i=0; i<n; i++) {
    printf(" %d", key->s2[i]);
    if ((i & 15) == 15) printf("\n");
  }
  printf("\n");

  printf("2 * (a * s1)[i] + (q + 2) * s2[i] mod q\n");
  for (i=0; i<n; i++) {
    printf(" %d", (2 * aux[i] + (q + 2) * key->s2[i]) % q);
    if ((i & 15) == 15) printf("\n");
  }
  printf("\n");

  printf("2 * (a * s1)[i] + (q + 2) * s2[i] mod 2\n");
  for (i=0; i<n; i++) {
    printf(" %d", (2 * aux[i] + (q + 2) * key->s2[i]) % 2);
    if ((i & 15) == 15) printf("\n");
  }
  printf("\n");

  printf("2 * (a * s1)[i] + (q + 2) * s2[i] mod 2q:\n");
  for (i=0; i<n; i++) {
    printf(" %d", (2 * aux[i] + (q + 2) * key->s2[i]) % p->q2);
    if ((i & 15) == 15) printf("\n");
  }
  printf("\n");

  printf("2 * zeta * (a * s1)[i] + s2[i] mod 2q:\n");
  for (i=0; i<n; i++) {
    printf(" %d", (2 * p->one_q2 * aux[i] + key->s2[i]) % p->q2);
    if ((i & 15) == 15) printf("\n");
  }
  printf("\n\n");
}
#endif

static int32_t bliss_b_private_key_init(bliss_private_key_t *private_key, bliss_kind_t kind){
  uint32_t n;
  int32_t *f = NULL, *g = NULL, *a = NULL;
  bliss_param_t p;

  if (! bliss_params_init(&p, kind)) {    
    return BLISS_B_BAD_ARGS;
  }

  n = p.n;

  f = calloc(n, sizeof(int32_t));
  if (f == NULL) {
      return BLISS_B_NO_MEM;
  }

  g = calloc(n, sizeof(int32_t));
  if (g == NULL) {
      free(f);
      return BLISS_B_NO_MEM;
  }

  a = calloc(n, sizeof(int32_t));
  if (a == NULL) {
      free(f);
      free(g);
      return BLISS_B_NO_MEM;
  }

  private_key->kind = kind;
  private_key->s1 = f;
  private_key->s2 = g;
  private_key->a = a;

  return BLISS_B_NO_ERROR;
}

/* Bliss-b public and sign key generation sign key is f, g small and f invertible
 *        public key is  a_q = -(2g-1)/f mod q = (2g'+1)/f  */
int32_t bliss_b_private_key_gen(bliss_private_key_t *private_key, bliss_kind_t kind, entropy_t *entropy) {
  int32_t retcode;
  uint32_t i, j;
  int32_t *t = NULL, *u = NULL;
  ntt_state_t state;
  bliss_param_t p;

  if (! bliss_params_init(&p, kind)) {
    return BLISS_B_BAD_ARGS;
  }

  assert(private_key != NULL);

  retcode = bliss_b_private_key_init(private_key, kind);

  if (retcode !=  BLISS_B_NO_ERROR) {
    return retcode;
  }

  state = init_ntt_state(kind);
  if (state == NULL) {
      secure_free(&t, p.n);
      secure_free(&u, p.n);
      delete_ntt_state(state);
      bliss_b_private_key_delete(private_key);
      return BLISS_B_NO_MEM;
  }

  t = calloc(p.n, sizeof(int32_t));
  if (t == NULL) {
      secure_free(&t, p.n);
      secure_free(&u, p.n);
      delete_ntt_state(state);
      bliss_b_private_key_delete(private_key);
      return BLISS_B_NO_MEM;
  }

  u = calloc(p.n, sizeof(int32_t));
  if (u == NULL) {
      secure_free(&t, p.n);
      secure_free(&u, p.n);
      delete_ntt_state(state);
      bliss_b_private_key_delete(private_key);
      return BLISS_B_NO_MEM;
  }

  /* randomize g */
  uniform_poly(private_key->s2, p.n, p.nz1, p.nz2, entropy);

  /* g = 2g - 1   N.B the Bliss-B paper uses 2g + 1 */
  for (i = 0; i < p.n; i++)
    private_key->s2[i] *= 2;
  private_key->s2[0] --;

  //N.B. ntt_t t
  forward_ntt(state, t, private_key->s2);

  /* find an invertible f  */
  for (j = 0; j < 4; j++) {

    /* randomize f  */
    uniform_poly(private_key->s1, p.n, p.nz1, p.nz2, entropy);

    /* Try again if f is not invertible. */
    if(!invert_polynomial(state, u, private_key->s1)){
      continue;
    }
    
    /* Success: u = ntt of f^-1. Compute a = (2g - 1)/f. */
    product_ntt(state, private_key->a, t,  u);
    inverse_ntt(state, private_key->a, private_key->a);

    // a = -1 * a
    negate_ntt(state, private_key->a);

    /* currently storing the private_key->a in ntt form */
    forward_ntt(state, private_key->a, private_key->a);

#if 0
    // BD: for debugging (iam: must do it before cleanup)
    check_key(private_key, &p, state);
#endif    
    secure_free(&t, p.n);
    secure_free(&u, p.n);
    delete_ntt_state(state);
    return BLISS_B_NO_ERROR;
  }

  return retcode;
}

void bliss_b_private_key_delete(bliss_private_key_t *private_key){
  bliss_param_t p;

  assert(private_key != NULL);
  
  if (! bliss_params_init(&p, private_key->kind)) {
    return;
  }

  secure_free(&private_key->s1, p.n);
  secure_free(&private_key->s2, p.n);
  secure_free(&private_key->a, p.n);
}


int32_t bliss_b_public_key_extract(bliss_public_key_t *public_key, const bliss_private_key_t * private_key){
  uint32_t n, i;
  int32_t *a, *b;

  assert(private_key != NULL && private_key->a != NULL);

  bliss_param_t p;

  
  if (! bliss_params_init(&p, private_key->kind)) {
    return BLISS_B_BAD_ARGS;
  }

  n = p.n;

  b = private_key->a;

  a = calloc(n, sizeof(int32_t));
  if (a == NULL) {
    return BLISS_B_NO_MEM;
  }

  for(i = 0; i < n; i++){
    a[i] = b[i];
  }

  public_key->kind = private_key->kind;
  public_key->a = a;

  return BLISS_B_NO_ERROR;
}


void bliss_b_public_key_delete(bliss_public_key_t *public_key){

  assert(public_key != NULL);

  free(public_key->a);
  public_key->a = NULL;
}
