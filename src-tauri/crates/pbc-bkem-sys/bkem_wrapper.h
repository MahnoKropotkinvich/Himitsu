/* Wrapper header that includes both PBC and BKEM, plus helper function declarations */
#include <pbc/pbc.h>
#include "bkem.h"

/* Wrapper functions for PBC inline/macro functions */
int himitsu_element_length_in_bytes(element_t e);
int himitsu_element_to_bytes(unsigned char *data, element_t e);
int himitsu_element_from_bytes(element_t e, unsigned char *data);
void himitsu_element_init_G1(element_t e, pairing_t pairing);
void himitsu_element_init_GT(element_t e, pairing_t pairing);
void himitsu_element_clear(element_t e);
int himitsu_element_cmp(element_t a, element_t b);
